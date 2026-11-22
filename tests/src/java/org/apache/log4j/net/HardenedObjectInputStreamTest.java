/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.RootLogger;

/**
 * Tests for {@link HardenedObjectInputStream} collection count limiting
 * that mitigates CVE-2023-26464.
 *
 * CVE-2023-26464: Deeply nested hash-based collection structures cause
 * exponential hashCode() computation during deserialization, leading
 * to Denial of Service. The fix limits the total number of Map/Collection
 * instances that can be deserialized in a single object graph.
 */
public class HardenedObjectInputStreamTest extends TestCase {

    /** How long a deserializing thread may run before it is considered hung. */
    private static final long HANG_TIMEOUT_MILLIS = 30000;

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * Builds deeply nested Hashtables (used as keys) that share children,
     * forming a DAG whose hashCode() costs O(2^depth) to compute while the
     * Hashtables are rebuilt during deserialization.
     */
    private static Hashtable buildNestedHashtable(int depth) {
        Hashtable root = new Hashtable();
        Hashtable s1 = root;
        Hashtable s2 = new Hashtable();
        for (int i = 0; i < depth; i++) {
            Hashtable t1 = new Hashtable();
            Hashtable t2 = new Hashtable();
            t1.put("foo", "bar");
            s1.put(t1, "x");
            s1.put(t2, "y");
            s2.put(t1, "x");
            s2.put(t2, "y");
            s1 = t1;
            s2 = t2;
        }
        return root;
    }

    private static LoggingEvent createEvent(Hierarchy hierarchy, String message, Map properties) {
        return new LoggingEvent(SocketNode.class.getName(), hierarchy.getLogger("remote"),
                System.currentTimeMillis(), Level.INFO, message, "main", null, null, null,
                properties);
    }

    private static Hashtable smallMdc(int i) {
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("requestId", "req-" + i);
        return mdc;
    }

    /**
     * Runs a SocketNode over the supplied serialized bytes and waits for it
     * to finish. Returns false if the node is still busy after the timeout.
     */
    private static boolean runSocketNode(StreamSocket socket, Hierarchy hierarchy)
            throws InterruptedException {
        SocketNode node = new SocketNode(socket, hierarchy);
        Thread thread = new Thread(node, "SocketNode-CVE-2023-26464");
        thread.setDaemon(true);
        thread.start();
        thread.join(HANG_TIMEOUT_MILLIS);
        return !thread.isAlive();
    }

    /**
     * CVE-2023-26464: The exact attack payload from the logback advisory.
     * Deeply nested HashSet structures that cause exponential hashCode()
     * computation. The collection count limit must reject this before
     * the computation becomes dangerous.
     */
    public void testDeeplyNestedHashSetRejected() throws Exception {
        // Build the CVE-2023-26464 attack payload: deeply nested HashSets
        // that form a DAG causing O(2^N) hashCode() computation
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        byte[] serialized = serialize(root);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        try {
            hois.readObject();
            fail("Deeply nested HashSet should be rejected due to collection count limit");
        } catch (InvalidObjectException e) {
            // Our resolveObject-based collection count limit caught it (pre-JDK 9)
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") >= 0);
        } catch (java.io.InvalidClassException e) {
            // On JDK 9+, the built-in ObjectInputFilter may reject it first
            // with "filter status: REJECTED". Either way, the attack is blocked.
        } finally {
            hois.close();
        }
    }

    /**
     * CVE-2023-26464: a logging event whose MDC carries deeply nested
     * Hashtables, read the way SocketNode and the chainsaw LoggingReceiver
     * read events, must be rejected instead of exhausting the CPU.
     */
    public void testLoggingEventWithNestedHashtableRejected() throws Exception {
        Hierarchy hierarchy = new Hierarchy(new RootLogger(Level.DEBUG));
        Hashtable properties = new Hashtable();
        properties.put("payload", buildNestedHashtable(100));
        byte[] serialized = serialize(createEvent(hierarchy, "attack", properties));

        HardenedLoggingEventInputStream hleis =
            new HardenedLoggingEventInputStream(new ByteArrayInputStream(serialized));
        try {
            hleis.readAdaptedObject();
            fail("Logging event with deeply nested Hashtables should be rejected");
        } catch (InvalidObjectException e) {
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") >= 0);
        } catch (java.io.InvalidClassException e) {
            // On JDK 9+, the built-in ObjectInputFilter may reject it first.
        } finally {
            hleis.close();
        }
    }

    /**
     * CVE-2023-26464 over the SocketServer path: SocketNode must drop the
     * connection on a nested collection payload instead of hanging, while
     * the legitimate event sent before it is still logged.
     */
    public void testSocketNodeDropsNestedCollectionEvent() throws Exception {
        Hierarchy hierarchy = new Hierarchy(new RootLogger(Level.DEBUG));
        CountingAppender appender = new CountingAppender();
        hierarchy.getRootLogger().addAppender(appender);

        Hashtable attack = new Hashtable();
        attack.put("payload", buildNestedHashtable(100));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(createEvent(hierarchy, "legit", smallMdc(0)));
        oos.writeObject(createEvent(hierarchy, "attack", attack));
        oos.writeObject(createEvent(hierarchy, "after", smallMdc(1)));
        oos.close();

        StreamSocket socket = new StreamSocket(bos.toByteArray());
        assertTrue("SocketNode hung deserializing nested collections",
                runSocketNode(socket, hierarchy));
        assertTrue("SocketNode should close the connection", socket.closeCalled);
        assertEquals(1, appender.count);
    }

    /**
     * The collection budget applies per event: a long-lived connection that
     * sends many events, each with an MDC, must keep working.
     */
    public void testSocketNodeAcceptsManyEventsWithMdc() throws Exception {
        Hierarchy hierarchy = new Hierarchy(new RootLogger(Level.DEBUG));
        CountingAppender appender = new CountingAppender();
        hierarchy.getRootLogger().addAppender(appender);

        int eventCount = HardenedObjectInputStream.MAX_COLLECTION_COUNT * 3;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < eventCount; i++) {
            oos.writeObject(createEvent(hierarchy, "event " + i, smallMdc(i)));
        }
        oos.close();

        StreamSocket socket = new StreamSocket(bos.toByteArray());
        assertTrue("SocketNode did not finish", runSocketNode(socket, hierarchy));
        assertEquals(eventCount, appender.count);
    }

    /**
     * A moderate number of nested collections (within the limit) should
     * still be allowed. This tests that normal LoggingEvent-like payloads
     * with a few Hashtables work fine.
     */
    public void testModerateCollectionsAllowed() throws Exception {
        // Simulate a LoggingEvent with MDC (Hashtable) containing a few entries
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("session", "abc123");
        mdc.put("requestId", "req-456");
        byte[] serialized = serialize(mdc);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        Object result = hois.readObject();
        assertTrue(result instanceof Hashtable);
        assertEquals("alice", ((Hashtable) result).get("user"));
        hois.close();
    }

    /**
     * Simple non-collection objects should work unaffected.
     */
    public void testStringAllowed() throws Exception {
        byte[] serialized = serialize("hello world");

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        assertEquals("hello world", hois.readObject());
        hois.close();
    }

    /** Unconnected socket that serves a fixed byte stream. */
    private static class StreamSocket extends Socket {
        private final InputStream in;
        volatile boolean closeCalled;

        StreamSocket(byte[] data) {
            this.in = new ByteArrayInputStream(data);
        }

        public InputStream getInputStream() {
            return in;
        }

        public synchronized void close() {
            closeCalled = true;
        }
    }

    /** Counts the events that reach the appender. */
    private static class CountingAppender extends AppenderSkeleton {
        volatile int count;

        protected void append(LoggingEvent event) {
            count++;
        }

        public void close() {
        }

        public boolean requiresLayout() {
            return false;
        }
    }
}
