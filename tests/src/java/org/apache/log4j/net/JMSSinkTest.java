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

import junit.framework.TestCase;

import javax.jms.Topic;
import javax.jms.TopicConnection;
import javax.jms.TopicConnectionFactory;
import javax.jms.TopicSession;
import javax.jms.TopicSubscriber;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.OperationNotSupportedException;
import javax.naming.spi.InitialContextFactory;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Hashtable;
import java.util.Vector;

/**
 * Checks that JMSSink only performs JNDI lookups in the java: namespace,
 * so that a TopicConnectionFactoryBindingName or TopicBindingName pointing
 * at an attacker controlled LDAP server is never resolved (CVE-2022-23302).
 */
public class JMSSinkTest extends TestCase {

  private static final String TCF_NAME = "java:comp/env/jms/TopicConnectionFactory";
  private static final String TOPIC_NAME = "java:comp/env/jms/Topic";

  /** Objects bound in the mock initial context. */
  static final Hashtable bindings = new Hashtable();

  /** Names resolved through the mock initial context. */
  static final Vector lookedUpNames = new Vector();

  /** Names of the methods invoked on the mock JMS objects. */
  static final Vector jmsCalls = new Vector();

  /** Listener registered on the mock topic subscriber. */
  static Object messageListener;

  private String previousContextFactory;
  private LdapTrap ldapTrap;

  public JMSSinkTest(String name) {
    super(name);
  }

  protected void setUp() throws Exception {
    bindings.clear();
    lookedUpNames.removeAllElements();
    jmsCalls.removeAllElements();
    messageListener = null;
    bindings.put(TCF_NAME, newJmsProxy(TopicConnectionFactory.class));
    bindings.put(TOPIC_NAME, newJmsProxy(Topic.class));

    previousContextFactory = System.getProperty(Context.INITIAL_CONTEXT_FACTORY);
    System.setProperty(Context.INITIAL_CONTEXT_FACTORY,
                       MockInitialContextFactory.class.getName());

    ldapTrap = new LdapTrap();
    ldapTrap.start();
  }

  protected void tearDown() throws Exception {
    ldapTrap.shutdown();
    if (previousContextFactory == null) {
      System.getProperties().remove(Context.INITIAL_CONTEXT_FACTORY);
    } else {
      System.setProperty(Context.INITIAL_CONTEXT_FACTORY, previousContextFactory);
    }
  }

  /**
   * Bindings in the java: namespace are still resolved and the sink
   * subscribes to the topic.
   */
  public void testSubscribesWithJavaNamespaceBindings() {
    JMSSink sink = new JMSSink(TCF_NAME, TOPIC_NAME, "user", "password");

    assertTrue(lookedUpNames.contains(TCF_NAME));
    assertTrue(lookedUpNames.contains(TOPIC_NAME));
    assertTrue(jmsCalls.contains("createSubscriber"));
    assertSame(sink, messageListener);
  }

  /**
   * A TopicConnectionFactoryBindingName pointing at an LDAP server must
   * not trigger a JNDI request to that server.
   */
  public void testLdapTopicConnectionFactoryBindingNameIsNotLookedUp() {
    new JMSSink(ldapTrap.url(), TOPIC_NAME, "user", "password");

    assertEquals("JMSSink contacted the LDAP server named by the "
                 + "TopicConnectionFactoryBindingName",
                 0, ldapTrap.getConnectionCount());
    assertFalse(jmsCalls.contains("createTopicConnection"));
    assertNull(messageListener);
  }

  /**
   * A TopicBindingName pointing at an LDAP server must not trigger a
   * JNDI request to that server.
   */
  public void testLdapTopicBindingNameIsNotLookedUp() {
    new JMSSink(TCF_NAME, ldapTrap.url(), "user", "password");

    assertEquals("JMSSink contacted the LDAP server named by the "
                 + "TopicBindingName",
                 0, ldapTrap.getConnectionCount());
    assertFalse(jmsCalls.contains("createSubscriber"));
    assertNull(messageListener);
  }

  /**
   * The lookup helper rejects names outside of the java: namespace and
   * still resolves names inside it.
   */
  public void testLookupRejectsNamesOutsideJavaNamespace() throws NamingException {
    Context ctx = new InitialContext();
    try {
      JMSSink.lookup(ctx, ldapTrap.url());
      fail("Expected a NamingException for a non java: name");
    } catch (NamingException e) {
      String msg = e.getMessage();
      assertTrue(String.valueOf(msg),
                 msg != null && msg.startsWith(JNDIUtil.RESTRICTION_MSG));
    }
    assertEquals("JMSSink.lookup contacted the LDAP server",
                 0, ldapTrap.getConnectionCount());

    assertSame(bindings.get(TCF_NAME), JMSSink.lookup(ctx, TCF_NAME));
  }

  static Object newJmsProxy(Class type) {
    return Proxy.newProxyInstance(JMSSinkTest.class.getClassLoader(),
                                  new Class[] { type }, new MockJmsHandler());
  }

  static Object invokeObjectMethod(Object proxy, Method method, Object[] args) {
    String name = method.getName();
    if (name.equals("equals")) {
      return proxy == args[0] ? Boolean.TRUE : Boolean.FALSE;
    }
    if (name.equals("hashCode")) {
      return new Integer(System.identityHashCode(proxy));
    }
    return "Mock" + proxy.getClass().getInterfaces()[0].getName();
  }

  /**
   * Initial context factory serving the objects in {@link #bindings}.
   */
  public static class MockInitialContextFactory implements InitialContextFactory {
    public Context getInitialContext(Hashtable environment) {
      return (Context) Proxy.newProxyInstance(JMSSinkTest.class.getClassLoader(),
                                              new Class[] { Context.class },
                                              new MockContextHandler());
    }
  }

  static class MockContextHandler implements InvocationHandler {
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
      if (method.getDeclaringClass() == Object.class) {
        return invokeObjectMethod(proxy, method, args);
      }
      String name = method.getName();
      if (name.equals("lookup")) {
        String jndiName = String.valueOf(args[0]);
        lookedUpNames.addElement(jndiName);
        Object bound = bindings.get(jndiName);
        if (bound == null) {
          throw new NameNotFoundException(jndiName);
        }
        return bound;
      }
      if (name.equals("close")) {
        return null;
      }
      throw new OperationNotSupportedException(name);
    }
  }

  static class MockJmsHandler implements InvocationHandler {
    public Object invoke(Object proxy, Method method, Object[] args) {
      if (method.getDeclaringClass() == Object.class) {
        return invokeObjectMethod(proxy, method, args);
      }
      String name = method.getName();
      jmsCalls.addElement(name);
      if (name.equals("createTopicConnection")) {
        return newJmsProxy(TopicConnection.class);
      }
      if (name.equals("createTopicSession")) {
        return newJmsProxy(TopicSession.class);
      }
      if (name.equals("createSubscriber")) {
        return newJmsProxy(TopicSubscriber.class);
      }
      if (name.equals("setMessageListener")) {
        messageListener = args[0];
        return null;
      }
      if (method.getReturnType() == Void.TYPE) {
        return null;
      }
      throw new UnsupportedOperationException(name);
    }
  }

  /**
   * Stands in for an attacker controlled LDAP server: records every
   * incoming connection and closes it right away.
   */
  static class LdapTrap extends Thread {
    private final ServerSocket serverSocket;
    private final Object lock = new Object();
    private int connectionCount;

    LdapTrap() throws IOException {
      super("LdapTrap");
      serverSocket = new ServerSocket(0, 5, InetAddress.getByName("127.0.0.1"));
      setDaemon(true);
    }

    String url() {
      return "ldap://127.0.0.1:" + serverSocket.getLocalPort() + "/cn=exploit";
    }

    int getConnectionCount() {
      synchronized (lock) {
        return connectionCount;
      }
    }

    public void run() {
      while (true) {
        Socket socket;
        try {
          socket = serverSocket.accept();
        } catch (IOException e) {
          return;
        }
        synchronized (lock) {
          connectionCount++;
        }
        try {
          socket.close();
        } catch (IOException e) {
          // ignore
        }
      }
    }

    void shutdown() throws Exception {
      serverSocket.close();
      join(5000);
    }
  }
}
