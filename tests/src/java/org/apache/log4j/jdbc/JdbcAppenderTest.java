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
package org.apache.log4j.jdbc;
import junit.framework.TestCase;

import org.apache.log4j.EnhancedPatternLayout;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.VectorErrorHandler;
import org.apache.log4j.spi.ErrorCode;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.xml.XLevel;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class JdbcAppenderTest extends TestCase {
    private static final String DB_URL = "jdbc:h2:mem:test_db";

    private static final String INSERT_SQL =
	"insert into logs(level,location,message,message2) values('%p','%c','%m', ' %c %p %m')";

    /**
     * Text which, when spliced verbatim into the SQL statement (CVE-2022-23305),
     * closes the string literal and makes the database run a sub-query.
     */
    private static final String INJECTION = "' || (select 'INJECTED') || '";

    // Closing the last connection to "in-memory h2" removes the database
    // So we keep the connection during the test
    // The logger opens its own connection
    Connection con;

    Logger logger = Logger.getLogger(JdbcAppenderTest.class);


    public void setUp() throws SQLException {
	try {
	    // Explicitly load the H2 driver
	    Class.forName("org.h2.Driver");
	} catch (ClassNotFoundException e) {
	    throw new RuntimeException("H2 Driver not found in classpath: " + e);
	}

	con = DriverManager.getConnection(DB_URL);
	Statement st = con.createStatement();
	try {
	    st.execute(
		    "create table logs(level varchar(100),location varchar(100),message varchar(100),message2 varchar(100))");
	} finally {
	    st.close();
	}
    }

    public void tearDown() throws SQLException {
	LogManager.shutdown();
	con.close();
    }

    public void testVerifyJdbcBufferSize1() throws SQLException {
	PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");


	String oldThreadName = Thread.currentThread().getName();
	try {
	    Thread.currentThread().setName("main");
	    logger.debug("message with ' quote");
	    assertEquals("batchSize=1, so messages should be added immediately",
		    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
		    joinSorted(getMessagesFromDababase()));

	    logger.fatal("message with \" quote");

	    assertEquals("batchSize=1, so two messages should be in DB after two logging calls",
		    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
			    + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL message with \" quote\n",
		    joinSorted(getMessagesFromDababase()));
	} finally {
	    Thread.currentThread().setName(oldThreadName);
	}
    }

    public void testVerifyJdbcBufferSize2() throws SQLException {
	PropertyConfigurator.configure("input/jdbc_h2_bufferSize2.properties");

	String oldThreadName = Thread.currentThread().getName();
	try {
	    Thread.currentThread().setName("main");
	    logger.log(XLevel.TRACE, "xtrace message");
	    logger.debug("message with ' quote");
	    logger.info("message with \" quote");
	    logger.warn("?");
	    // bufferSize=2, so this messsage won't yet be stored to the db
	    logger.error("m4");

	    assertEquals(
		    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
			    + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
			    + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
			    + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
		    joinSorted(getMessagesFromDababase()));

	    logger.fatal("m5");

	    assertEquals("Logging m5 message should trigger buffer flush for both m4 and m5",
		    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
			    + "ERROR; org.apache.log4j.jdbc.JdbcAppenderTest; m4;  org.apache.log4j.jdbc.JdbcAppenderTest ERROR m4\n"
			    + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; m5;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL m5\n"
			    + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
			    + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
			    + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
		    joinSorted(getMessagesFromDababase()));
	} finally {
	    Thread.currentThread().setName(oldThreadName);
	}
    }

    /**
     * CVE-2022-23305: a logged message that closes the SQL string literal must
     * be stored verbatim instead of being executed by the database.
     */
    public void testSqlInjectionInMessageIsNotExecuted() throws SQLException {
	PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");

	logger.warn(INJECTION);

	assertEquals("message must be bound as a parameter, not spliced into the SQL",
		"WARN; org.apache.log4j.jdbc.JdbcAppenderTest; " + INJECTION
			+ ";  org.apache.log4j.jdbc.JdbcAppenderTest WARN " + INJECTION + "\n",
		joinSorted(getMessagesFromDababase()));
    }

    /**
     * CVE-2022-23305: the batched (bufferSize &gt; 1) code path must bind the
     * message as a parameter as well.
     */
    public void testSqlInjectionInBatchIsNotExecuted() throws SQLException {
	PropertyConfigurator.configure("input/jdbc_h2_bufferSize2.properties");

	logger.info(INJECTION);
	logger.warn(INJECTION);

	assertEquals("batched messages must be bound as parameters, not spliced into the SQL",
		"INFO; org.apache.log4j.jdbc.JdbcAppenderTest; " + INJECTION
			+ ";  org.apache.log4j.jdbc.JdbcAppenderTest INFO " + INJECTION + "\n"
			+ "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; " + INJECTION
			+ ";  org.apache.log4j.jdbc.JdbcAppenderTest WARN " + INJECTION + "\n",
		joinSorted(getMessagesFromDababase()));
    }

    /**
     * CVE-2022-23305: values coming from the MDC are bound as parameters too.
     */
    public void testSqlInjectionInMdcIsNotExecuted() throws SQLException {
	VectorErrorHandler errorHandler = new VectorErrorHandler();
	JDBCAppender appender = createAppender(errorHandler);
	appender.setSql("insert into logs(level,location,message,message2) values('%p','%c','%m','%X{user}')");

	MDC.put("user", INJECTION);
	try {
	    appender.doAppend(createEvent(Level.WARN, "mdc"));
	} finally {
	    MDC.remove("user");
	    appender.close();
	}

	assertEquals("MDC value must be bound as a parameter, not spliced into the SQL",
		"WARN; org.apache.log4j.jdbc.JdbcAppenderTest; mdc; " + INJECTION + "\n",
		joinSorted(getMessagesFromDababase()));
	assertEquals(0, errorHandler.size());
    }

    /**
     * CVE-2022-23305: conversion specifiers outside of a quoted SQL literal
     * are never expanded into the statement text.
     */
    public void testUnquotedConversionPatternIsNotExpanded() throws SQLException {
	VectorErrorHandler errorHandler = new VectorErrorHandler();
	JDBCAppender appender = createAppender(errorHandler);
	appender.setSql("insert into logs(level,location,message,message2) values('%p','%c','%m',%m)");

	try {
	    appender.doAppend(createEvent(Level.WARN, "(select 40+2)"));
	} finally {
	    appender.close();
	}

	assertEquals("the unquoted %m must not be replaced by the message",
		"", joinSorted(getMessagesFromDababase()));
	assertTrue("the statement with a bare %m should be rejected by the database",
		errorHandler.size() > 0);
	assertTrue(errorHandler.getException(0) instanceof SQLException);
    }

    /**
     * CVE-2022-23305: only PatternLayout can be turned into a prepared
     * statement, any other layout is refused rather than executed as SQL.
     */
    public void testNonPatternLayoutIsRejected() throws SQLException {
	VectorErrorHandler errorHandler = new VectorErrorHandler();
	JDBCAppender appender = createAppender(errorHandler);
	appender.setLayout(new EnhancedPatternLayout(INSERT_SQL));

	try {
	    appender.doAppend(createEvent(Level.WARN, INJECTION));
	} finally {
	    appender.close();
	}

	assertEquals("a layout other than PatternLayout must not produce SQL",
		"", joinSorted(getMessagesFromDababase()));
	assertEquals(1, errorHandler.size());
	assertEquals(ErrorCode.MISSING_LAYOUT, errorHandler.getErrorCode(0));
    }

    /**
     * The statement may still be configured through the PatternLayout's
     * ConversionPattern instead of the sql option.
     */
    public void testLayoutConversionPatternIsUsedAsStatement() throws SQLException {
	VectorErrorHandler errorHandler = new VectorErrorHandler();
	JDBCAppender appender = createAppender(errorHandler);
	appender.setLayout(new PatternLayout(INSERT_SQL));

	try {
	    appender.doAppend(createEvent(Level.INFO, "from layout"));
	} finally {
	    appender.close();
	}

	assertEquals(
		"INFO; org.apache.log4j.jdbc.JdbcAppenderTest; from layout;  org.apache.log4j.jdbc.JdbcAppenderTest INFO from layout\n",
		joinSorted(getMessagesFromDababase()));
	assertEquals(0, errorHandler.size());
    }

    private JDBCAppender createAppender(VectorErrorHandler errorHandler) {
	JDBCAppender appender = new JDBCAppender();
	appender.setURL(DB_URL);
	appender.setUser("");
	appender.setPassword("");
	appender.setErrorHandler(errorHandler);
	return appender;
    }

    private LoggingEvent createEvent(Level level, String message) {
	return new LoggingEvent(Logger.class.getName(), logger, level, message, null);
    }

    private static String joinSorted(List list) {
	Collections.sort(list);
	StringBuffer sb = new StringBuffer();
	for (int i = 0; i < list.size(); i++) {
	    String s = (String) list.get(i);
	    sb.append(s).append('\n');
	}
	return sb.toString();
    }

    private List getMessagesFromDababase() throws SQLException {
	List res = new ArrayList();
	PreparedStatement ps = con.prepareStatement("select level,location,message,message2 from logs");
	try {
	    ResultSet rs = ps.executeQuery();
	    try {
		while (rs.next()) {
		    res.add(rs.getString(1) + "; " + rs.getString(2) + "; " + rs.getString(3) + "; " + rs.getString(4));
		}
	    } finally {
		rs.close();
	    }
	} finally {
	    ps.close();
	}
	return res;
    }
}
