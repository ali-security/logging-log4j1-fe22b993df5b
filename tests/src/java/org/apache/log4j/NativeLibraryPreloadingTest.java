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
package org.apache.log4j;

import java.io.StringReader;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.TestCase;

import org.apache.log4j.xml.DOMConfigurator;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

/**
 * Regression tests for sonatype-2010-0053 (DLL preloading).
 *
 * <p>NTEventLogAppender loaded its native library with
 * System.loadLibrary("NTEventLogAppender...") from a static initializer,
 * i.e. by an unqualified name resolved against the library search path,
 * which allowed a planted DLL to be loaded. The appender has been removed,
 * so neither loading the class nor naming it in a configuration file may
 * trigger a native library load any more.
 */
public class NativeLibraryPreloadingTest extends TestCase {

    private static final String NT_APPENDER_CLASS =
            "org.apache.log4j.nt.NTEventLogAppender";

    public NativeLibraryPreloadingTest(final String testName) {
        super(testName);
    }

    /**
     * Clean up configuration after each test.
     */
    public void tearDown() {
        LogManager.resetConfiguration();
    }

    /**
     * Loading the class used to run its static initializer, which searched
     * the library path for NTEventLogAppender.dll.
     */
    public void testNTEventLogAppenderClassIsNotAvailable() {
        try {
            Class.forName(NT_APPENDER_CLASS);
            fail(NT_APPENDER_CLASS + " must not be available");
        } catch (ClassNotFoundException expected) {
            // the class and its native library loader are gone
        } catch (LinkageError e) {
            fail("Loading " + NT_APPENDER_CLASS
                    + " attempted to load a native library: " + e);
        }
    }

    /**
     * A properties configuration naming the appender must not load
     * a native library.
     */
    public void testPropertyConfiguratorDoesNotLoadNativeLibrary() {
        Properties props = new Properties();
        props.setProperty("log4j.rootLogger", "DEBUG, NT");
        props.setProperty("log4j.appender.NT", NT_APPENDER_CLASS);
        props.setProperty("log4j.appender.NT.Source", "log4j");
        props.setProperty("log4j.appender.NT.layout",
                "org.apache.log4j.SimpleLayout");
        try {
            PropertyConfigurator.configure(props);
        } catch (LinkageError e) {
            fail("Configuring " + NT_APPENDER_CLASS
                    + " attempted to load a native library: " + e);
        }
        assertNull(Logger.getRootLogger().getAppender("NT"));
    }

    /**
     * An XML configuration naming the appender must not load
     * a native library.
     */
    public void testDOMConfiguratorDoesNotLoadNativeLibrary() throws Exception {
        String xml =
            "<log4j:configuration>"
            + "<appender name=\"NT\" class=\"" + NT_APPENDER_CLASS + "\">"
            + "<param name=\"Source\" value=\"log4j\"/>"
            + "<layout class=\"org.apache.log4j.SimpleLayout\"/>"
            + "</appender>"
            + "<root><level value=\"debug\"/><appender-ref ref=\"NT\"/></root>"
            + "</log4j:configuration>";
        Element element = DocumentBuilderFactory.newInstance()
                .newDocumentBuilder()
                .parse(new InputSource(new StringReader(xml)))
                .getDocumentElement();
        try {
            DOMConfigurator.configure(element);
        } catch (LinkageError e) {
            fail("Configuring " + NT_APPENDER_CLASS
                    + " attempted to load a native library: " + e);
        }
        assertNull(Logger.getRootLogger().getAppender("NT"));
    }
}
