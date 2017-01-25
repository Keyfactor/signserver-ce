/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.timemonitor.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URLDecoder;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.TimeZone;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.signserver.timemonitor.common.LeapState;
import org.signserver.timemonitor.common.ReportState;
import org.signserver.timemonitor.common.TimeMonitorRuntimeConfig;
import org.signserver.timemonitor.common.TimeState;
import org.signserver.timemonitor.ntp.AbstractResult;
import org.signserver.timemonitor.ntp.NTPDateCommand;
import org.signserver.timemonitor.ntp.NTPDateParser;
import org.signserver.timemonitor.ntp.NTPDateResult;
import org.signserver.timemonitor.ntp.NTPQCommand;
import org.signserver.timemonitor.ntp.NTPQResult;

/**
 * Tests for the TimeMonitorRunnable class.
 *
 * @author Markus Kilås
 * @version $Id: TimeMonitorRunnableTest.java 5792 2013-09-04 11:40:45Z netmackan $
 */
public class TimeMonitorRunnableTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeMonitorRunnableTest.class);

    private static final Properties runProperties;
    private static final String PROP_HOST = "192.168.10.200";
    private static final int PROP_SENDSAMPLES = 4;
    private static final double PROP_TIMEOUT = 0.3;
    private static final int PROP_MAX_ACCEPTED_OFFSET = 995;
    private static final int PROP_WARN_OFFSET = 498;
    private static final int PROP_STATUS_EXPIRE_TIME = 901;
    private static final int PROP_LEAPSTATUS_EXPIRE_TIME = 60000;
    private static final int PROP_MIN_RUN_TIME = 102;
    private static final int PROP_WARN_RUN_TIME = 7003;
    static {
        runProperties = new Properties();
        runProperties.setProperty(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_HOST, PROP_HOST);
        runProperties.setProperty(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_SENDSAMPLES, String.valueOf(PROP_SENDSAMPLES));
        runProperties.setProperty(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_TIMEOUT, String.valueOf(PROP_TIMEOUT));

        runProperties.setProperty(TimeMonitorRuntimeConfig.PROPERTY_MAX_ACCEPTED_OFFSET, String.valueOf(PROP_MAX_ACCEPTED_OFFSET));
        runProperties.setProperty(TimeMonitorRuntimeConfig.PROPERTY_WARN_OFFSET, String.valueOf(PROP_WARN_OFFSET));
        runProperties.setProperty(TimeMonitorRuntimeConfig.PROPERTY_STATUS_EXPIRE_TIME, String.valueOf(PROP_STATUS_EXPIRE_TIME));
        runProperties.setProperty(TimeMonitorRuntimeConfig.PROPERTY_LEAPSTATUS_EXPIRE_TIME, String.valueOf(PROP_LEAPSTATUS_EXPIRE_TIME));
        runProperties.setProperty(TimeMonitorRuntimeConfig.PROPERTY_MIN_RUN_TIME, String.valueOf(PROP_MIN_RUN_TIME));
        runProperties.setProperty(TimeMonitorRuntimeConfig.PROPERTY_WARN_RUN_TIME, String.valueOf(PROP_WARN_RUN_TIME));
    }


    /**
     * Test of runRound method, of class TimeMonitorRunnable.
     * @throws java.lang.Exception
     */
    @Test
    public void testRunRoundCallsTasks() throws Exception {
        LOG.info("runRoundCallsTasks");

        TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(TimeMonitorAppConfigTest.getAppProperties());
        final List<String> errors = new LinkedList<>();
        TimeMonitorRuntimeConfig runConfig = TimeMonitorRuntimeConfig.load(getRunProperties(), errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }
        final MockResults mockResults = new MockResults();
        MockTimeMonitorRunnable instance = new MockTimeMonitorRunnable(appConfig, runConfig) {

            @Override
            protected NTPDateResult queryTask() {
                mockResults.queryTaskCalled = true;
                return new NTPDateResult(0, null, "server1", 1, 0.01, 0.02, false);
            }

            @Override
            protected NTPQResult leapSecondQueryTask() {
                mockResults.leapSecondQueryTaskCalled = true;
                return new NTPQResult(0, null, LeapState.NONE);
            }

            @Override
            protected TimeState timeTask(NTPDateResult ntpDate, boolean forceLogging) {
                mockResults.timeTaskCalled = true;
                return TimeState.INSYNC;
            }

            @Override
            protected ReportState reportTask(TimeState timeState, LeapState leapState, long currentTime) {
                mockResults.reportTaskCalled = true;
                return ReportState.REPORTED;
            }

        };
        instance.runRound();

        assertTrue("query task called", mockResults.queryTaskCalled);
        assertTrue("leap second query task called", mockResults.leapSecondQueryTaskCalled);
        assertTrue("time task called", mockResults.timeTaskCalled);
        assertTrue("report task called", mockResults.reportTaskCalled);
    }

    /**
     * Tests that in managed config mode, there is not query until a config is
     * obtained.
     * @throws java.lang.Exception
     */
    @Test
    public void testNoQueryUntilReceivedConfig() throws Exception {
        LOG.info("testNoQueryUntilReceivedConfig");

        // Enable SignServer managed config
        final Properties appProperties = new Properties();
        appProperties.putAll(TimeMonitorAppConfigTest.getAppProperties());
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_MANAGEDCONFIG, Boolean.TRUE.toString());

        final TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(appProperties);
        final TimeMonitorRuntimeConfig runConfig = new TimeMonitorRuntimeConfig();
        final List<String> errors = new LinkedList<>();
        final Properties nextRunProperties = getRunProperties();
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }

        final MockResults mockResults = new MockResults();
        MockTimeMonitorRunnable instance = new MockTimeMonitorRunnable(appConfig, runConfig) {

            private int round;

            @Override
            protected NTPDateResult queryTask() {
                mockResults.queryTaskCalled = true;
                return new NTPDateResult(0, null, "server1", 1, 0.01, 0.02, false);
            }

            @Override
            protected NTPQResult leapSecondQueryTask() {
                mockResults.leapSecondQueryTaskCalled = true;
                return new NTPQResult(0, null, LeapState.NONE);
            }

            @Override
            protected TimeState timeTask(NTPDateResult ntpDate, boolean forceLogging) {
                mockResults.timeTaskCalled = true;
                return TimeState.INSYNC;
            }

            @Override
            protected byte[] postReport(String body) throws UnsupportedEncodingException, MalformedURLException, IOException {
                round++;
                mockResults.reportTaskCalled = true;

                // Now get some config
                if (round == 2) {
                    // Simulate that we got some config
                    return createMockResponse(nextRunProperties, "1002");
                } else {
                    return new byte[0];
                }
            }
        };

        // 1st round, no config
        instance.runRound();
        assertFalse("query task called", mockResults.queryTaskCalled);
        assertFalse("leap second query task called", mockResults.leapSecondQueryTaskCalled);
        assertFalse("time task called", mockResults.timeTaskCalled);
        assertTrue("report task called", mockResults.reportTaskCalled);
        mockResults.reset();

        // 2nd round, no config still
        instance.runRound();
        assertFalse("query task called", mockResults.queryTaskCalled);
        assertFalse("leap second query task called", mockResults.leapSecondQueryTaskCalled);
        assertFalse("time task called", mockResults.timeTaskCalled);
        assertTrue("report task called", mockResults.reportTaskCalled);
        mockResults.reset();

        // 3rd round, now query should have been called
        instance.runRound();
        assertTrue("query task called", mockResults.queryTaskCalled);
        assertTrue("leap second query task called", mockResults.leapSecondQueryTaskCalled);
        assertTrue("time task called", mockResults.timeTaskCalled);
        assertTrue("report task called", mockResults.reportTaskCalled);
        mockResults.reset();

        // 4th round, query should still be called
        instance.runRound();
        assertTrue("query task called", mockResults.queryTaskCalled);
        assertTrue("leap second query task called", mockResults.leapSecondQueryTaskCalled);
        assertTrue("time task called", mockResults.timeTaskCalled);
        assertTrue("report task called", mockResults.reportTaskCalled);
        mockResults.reset();
    }

    /**
     * Tests that there is no query when explicitly disabled.
     * @throws java.lang.Exception
     */
    @Test
    public void testNoQueryWhenDisabled() throws Exception {
        LOG.info("testNoQueryWhenDisabled");

        // Enable SignServer managed config
        final Properties appProperties = new Properties();
        appProperties.putAll(TimeMonitorAppConfigTest.getAppProperties());
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_MANAGEDCONFIG, Boolean.TRUE.toString());

        final TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(appProperties);
        final TimeMonitorRuntimeConfig runConfig = new TimeMonitorRuntimeConfig();
        final Properties nextRunProperties = new Properties();
        nextRunProperties.putAll(getRunProperties());
        nextRunProperties.setProperty(TimeMonitorRuntimeConfig.PROPERTY_DISABLED, String.valueOf(true));

        final MockResults mockResults = new MockResults();
        MockTimeMonitorRunnable instance = new MockTimeMonitorRunnable(appConfig, runConfig) {

            private int round;

            @Override
            protected NTPDateResult queryTask() {
                mockResults.queryTaskCalled = true;
                return new NTPDateResult(0, null, "server1", 1, 0.01, 0.02, false);
            }

            @Override
            protected NTPQResult leapSecondQueryTask() {
                mockResults.leapSecondQueryTaskCalled = true;
                return new NTPQResult(0, null, LeapState.NONE);
            }

            @Override
            protected TimeState timeTask(NTPDateResult ntpDate, boolean forceLogging) {
                mockResults.timeTaskCalled = true;
                return TimeState.INSYNC;
            }

            @Override
            protected byte[] postReport(String body) throws UnsupportedEncodingException, MalformedURLException, IOException {
                round++;
                mockResults.reportTaskCalled = true;

                // Simulate that we got some config
                return createMockResponse(nextRunProperties, "1003");
            }

        };

        // 1st round, no config
        instance.runRound();
        assertFalse("query task called", mockResults.queryTaskCalled);
        assertFalse("leap second query task called", mockResults.leapSecondQueryTaskCalled);
        assertFalse("time task called", mockResults.timeTaskCalled);
        assertTrue("report task called", mockResults.reportTaskCalled);
        mockResults.reset();

        // 2nd round, now disabled so no query
        instance.runRound();
        assertFalse("query task called", mockResults.queryTaskCalled);
        assertFalse("leap second query task called", mockResults.leapSecondQueryTaskCalled);
        assertFalse("time task called", mockResults.timeTaskCalled);
        assertTrue("report task called", mockResults.reportTaskCalled);
        mockResults.reset();

        // 3rd round, still disabled
        instance.runRound();
        assertFalse("query task called", mockResults.queryTaskCalled);
        assertFalse("leap second query task called", mockResults.leapSecondQueryTaskCalled);
        assertFalse("time task called", mockResults.timeTaskCalled);
        assertTrue("report task called", mockResults.reportTaskCalled);
        mockResults.reset();

    }

    /**
     * Tests that there is no query when disabled by incorrect config.
     * @throws java.lang.Exception
     */
    @Test
    public void testNoQueryWhenIncorrectConfig() throws Exception {
        LOG.info("testNoQueryWhenIncorrectConfig");

        // Enable SignServer managed config
        final Properties appProperties = new Properties();
        appProperties.putAll(TimeMonitorAppConfigTest.getAppProperties());
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_MANAGEDCONFIG, Boolean.TRUE.toString());

        final TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(appProperties);
        final TimeMonitorRuntimeConfig runConfig = new TimeMonitorRuntimeConfig();
        final Properties nextRunProperties = new Properties();
        nextRunProperties.putAll(getRunProperties());
        nextRunProperties.setProperty(TimeMonitorRuntimeConfig.PROPERTY_MAX_ACCEPTED_OFFSET, "not-an-integer");

        final MockResults mockResults = new MockResults();
        MockTimeMonitorRunnable instance = new MockTimeMonitorRunnable(appConfig, runConfig) {

            private int round;

            @Override
            protected NTPDateResult queryTask() {
                mockResults.queryTaskCalled = true;
                return new NTPDateResult(0, null, "server1", 1, 0.01, 0.02, false);
            }

            @Override
            protected NTPQResult leapSecondQueryTask() {
                mockResults.leapSecondQueryTaskCalled = true;
                return new NTPQResult(0, null, LeapState.NONE);
            }

            @Override
            protected TimeState timeTask(NTPDateResult ntpDate, boolean forceLogging) {
                mockResults.timeTaskCalled = true;
                return TimeState.INSYNC;
            }

            @Override
            protected byte[] postReport(String body) throws UnsupportedEncodingException, MalformedURLException, IOException {
                round++;
                mockResults.reportTaskCalled = true;

                // Simulate that we got some config
                return createMockResponse(nextRunProperties, "1004");
            }

        };

        // 1st round, no config
        instance.runRound();
        assertFalse("query task called", mockResults.queryTaskCalled);
        assertFalse("leap second query task called", mockResults.leapSecondQueryTaskCalled);
        assertFalse("time task called", mockResults.timeTaskCalled);
        assertTrue("report task called", mockResults.reportTaskCalled);
        mockResults.reset();

        // 2nd round, now incorrect config, so disabled
        instance.runRound();
        assertFalse("query task called", mockResults.queryTaskCalled);
        assertFalse("leap second query task called", mockResults.leapSecondQueryTaskCalled);
        assertFalse("time task called", mockResults.timeTaskCalled);
        assertTrue("report task called", mockResults.reportTaskCalled);
        mockResults.reset();

        // 3rd round, still disabled
        instance.runRound();
        assertFalse("query task called", mockResults.queryTaskCalled);
        assertFalse("leap second query task called", mockResults.leapSecondQueryTaskCalled);
        assertFalse("time task called", mockResults.timeTaskCalled);
        assertTrue("report task called", mockResults.reportTaskCalled);
        mockResults.reset();

    }

    /**
     * Tests the report generation.
     * @throws java.lang.Exception
     */
    @Test
    public void testCreateReportBody_managedConf() throws Exception {
        LOG.info("testCreateReportBody");

        final Properties appProperties = new Properties();
        appProperties.putAll(TimeMonitorAppConfigTest.getAppProperties());
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_MANAGEDCONFIG, Boolean.TRUE.toString());
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_STATUSPROPERTIESWORKER_NAME, "MyTimeMonitorManager");

        final TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(appProperties);
        final TimeMonitorRuntimeConfig runConfig = new TimeMonitorRuntimeConfig();

        MockTimeMonitorRunnable instance = new MockTimeMonitorRunnable(appConfig, runConfig) {

            private int round;

            @Override
            protected NTPDateResult queryTask() {
                return new NTPDateResult(0, null, "server1", 1, 0.01, 0.02, false);
            }

            @Override
            protected NTPQResult leapSecondQueryTask() {
                return new NTPQResult(0, null, LeapState.NONE);
            }

            @Override
            protected TimeState timeTask(NTPDateResult ntpDate, boolean forceLogging) {
                return TimeState.INSYNC;
            }

            @Override
            protected byte[] postReport(String body) throws UnsupportedEncodingException, MalformedURLException, IOException {
                return new byte[0];
            }
        };

        instance.runRound();

        String reportBody = instance.createReportBody(true, LeapState.NONE, 111L, 222L, 333L);
        assertTrue("worker name in: " + reportBody, reportBody.contains("workerName=MyTimeMonitorManager"));
        String data = reportBody.substring(reportBody.indexOf("data=") + "data=".length(), reportBody.length()); // Assumes data to be last, might need adjustment in future
        Properties request = new Properties();
        request.load(new StringReader(URLDecoder.decode(data, "ISO-8859-1")));

        // Example: {CONFIG=0000, LEAPSECOND.EXPIRATION=222, TIMESOURCE0_INSYNC.EXPIRATION=111, TIMEMONITOR_STATE.VALUE=1409154212442,UNKNOWN,REPORTED,UNKNOWN,0000,0,0,0,1, TIMESOURCE0_INSYNC.VALUE=true, LEAPSECOND.VALUE=NONE, TIMEMONITOR_LOG.VALUE=2014-08-27 17:43:32,444 INFO  State changed to: UNKNOWN,REPORTED,UNKNOWN
        // , TIMEMONITOR_STATE.EXPIRATION=333}
        assertEquals("true", request.getProperty("TIMESOURCE0_INSYNC.VALUE"));
        assertEquals("NONE", request.getProperty("LEAPSECOND.VALUE"));
        assertEquals("111", request.getProperty("TIMESOURCE0_INSYNC.EXPIRATION"));
        assertEquals("222", request.getProperty("LEAPSECOND.EXPIRATION"));
        assertEquals("requests config", runConfig.getVersion(), request.getProperty("CONFIG"));
    }

    /**
     * Tests the report generation.
     * @throws java.lang.Exception
     */
    @Test
    public void testCreateReportBody_staticConf() throws Exception {
        LOG.info("testCreateReportBody");

        final Properties appProperties = new Properties();
        appProperties.putAll(TimeMonitorAppConfigTest.getAppProperties());
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_MANAGEDCONFIG, Boolean.FALSE.toString());
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_STATUSPROPERTIESWORKER_NAME, "MyTimeMonitorManager");

        final TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(appProperties);
        final TimeMonitorRuntimeConfig runConfig = new TimeMonitorRuntimeConfig();

        MockTimeMonitorRunnable instance = new MockTimeMonitorRunnable(appConfig, runConfig) {

            private int round;

            @Override
            protected NTPDateResult queryTask() {
                return new NTPDateResult(0, null, "server1", 1, 0.01, 0.02, false);
            }

            @Override
            protected NTPQResult leapSecondQueryTask() {
                return new NTPQResult(0, null, LeapState.NONE);
            }

            @Override
            protected TimeState timeTask(NTPDateResult ntpDate, boolean forceLogging) {
                return TimeState.INSYNC;
            }

            @Override
            protected byte[] postReport(String body) throws UnsupportedEncodingException, MalformedURLException, IOException {
                return new byte[0];
            }
        };

        instance.runRound();

        String reportBody = instance.createReportBody(true, LeapState.NONE, 111L, 222L, 333L);
        assertTrue("worker name in: " + reportBody, reportBody.contains("workerName=MyTimeMonitorManager"));
        String data = reportBody.substring(reportBody.indexOf("data=") + "data=".length(), reportBody.length()); // Assumes data to be last, might need adjustment in future
        Properties request = new Properties();
        request.load(new StringReader(URLDecoder.decode(data, "ISO-8859-1")));

        // Example: {LEAPSECOND.EXPIRATION=222, TIMESOURCE0_INSYNC.EXPIRATION=111, TIMEMONITOR_STATE.VALUE=1409154212442,UNKNOWN,REPORTED,UNKNOWN,0000,0,0,0,1, TIMESOURCE0_INSYNC.VALUE=true, LEAPSECOND.VALUE=NONE, TIMEMONITOR_LOG.VALUE=2014-08-27 17:43:32,444 INFO  State changed to: UNKNOWN,REPORTED,UNKNOWN
        // , TIMEMONITOR_STATE.EXPIRATION=333}
        assertEquals("true", request.getProperty("TIMESOURCE0_INSYNC.VALUE"));
        assertEquals("NONE", request.getProperty("LEAPSECOND.VALUE"));
        assertEquals("111", request.getProperty("TIMESOURCE0_INSYNC.EXPIRATION"));
        assertEquals("222", request.getProperty("LEAPSECOND.EXPIRATION"));
        assertNull("requests no config", request.getProperty("CONFIG"));

    }

    private static byte[] createMockResponse(Properties newConfig, String version) throws IOException {
        final byte[] result;
        if (version == null) {
            result = new byte[0];
        } else {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Properties props = new Properties();
            props.putAll(newConfig);
            props.setProperty("CONFIG", version);
            props.store(out, null);
            result = out.toByteArray();
        }
        return result;
    }

    /**
     * Exercises the runRound method with changes from INSYNC to OUT_OF_SYNC etc.
     * The log output can be manually inspected.
     * @throws java.lang.Exception
     */
    @Test
    public void testLogLastTrustedTime() throws Exception {
        LOG.info("logLastTrustedTime");

        final MockStateHolder mockState = new MockStateHolder();
        final TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(TimeMonitorAppConfigTest.getAppProperties());
        final List<String> errors = new LinkedList<>();
        final TimeMonitorRuntimeConfig runConfig = TimeMonitorRuntimeConfig.load(getRunProperties(), errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }
        MockTimeMonitorRunnable instance = new MockTimeMonitorRunnable(appConfig, runConfig) {

            @Override
            protected NTPDateResult queryTask() {
                return new NTPDateResult(0, null, "server1", 1, 0.01, 0.02, false);
            }

            @Override
            protected TimeState timeTask(NTPDateResult ntpDate, boolean forceLogging) {
                return mockState.getTimeState();
            }

            @Override
            protected ReportState reportTask(TimeState timeState, LeapState leapState, long currentTime) {
                return mockState.getReportState();
            }

        };
        mockState.lastUpdated = System.currentTimeMillis();
        mockState.reportState = ReportState.REPORTED;

        // Run one round were the time is insync
        mockState.timeState = TimeState.INSYNC;
        instance.runRound();

        // Now run when the time is out of sync and manually check that it was
        // logged correctly
        mockState.timeState = TimeState.OUT_OF_SYNC;
        instance.runRound();

        // Run one round were the time is insync
        mockState.timeState = TimeState.INSYNC;
        instance.runRound();

        // Now run when the time is unknown and manually check that it was
        // logged correctly
        mockState.timeState = TimeState.UNKNOWN;
        instance.runRound();

        // Run one round were the time is insync
        mockState.timeState = TimeState.SOON_OUT_OF_SYNC;
        instance.runRound();

        // Now run when the time is out of sync and manually check that it was
        // logged correctly
        mockState.timeState = TimeState.OUT_OF_SYNC;
        instance.runRound();

        // Run one round were the time is insync
        mockState.timeState = TimeState.INSYNC;
        instance.runRound();

        // Run one round were the time is insync
        mockState.timeState = TimeState.SOON_OUT_OF_SYNC;
        instance.runRound();

        // Now run when the time is unknown and manually check that it was
        // logged correctly
        mockState.timeState = TimeState.UNKNOWN;
        instance.runRound();
    }

    /**
     * Tests that the quertTask executes the ntpdate command.
     * @throws java.lang.Exception
     */
    @Test
    public void testQueryTask() throws Exception {
        LOG.info("queryTasks");

        TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(TimeMonitorAppConfigTest.getAppProperties());
        final List<String> errors = new LinkedList<>();
        TimeMonitorRuntimeConfig runConfig = TimeMonitorRuntimeConfig.load(getRunProperties(), errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }

        final MockResults mockResults = new MockResults();

        NTPDateCommand mockedNtpDateCommand = new NTPDateCommand("ntpdate", "server4") {
            @Override
            public NTPDateResult execute() throws IOException {
                mockResults.ntpDateCommandCalled = true;
                return new NTPDateResult(-1, "Mocked test", "server4", 16, 11.0, 3.0, false);
            }
        };

        NTPQCommand mockedNtpQCommand = new NTPQCommand("ntpq", 0) {
            @Override
            public NTPQResult execute() throws IOException {
                mockResults.ntpQCommandCalled = true;
                return new NTPQResult(-1, "Mocked test", LeapState.NONE);
            }
        };

        TimeMonitorRunnable instance = new TimeMonitorRunnable(appConfig, runConfig, mockedNtpDateCommand, mockedNtpQCommand, 1000);
        instance.queryTask();
        instance.leapSecondQueryTask();
        assertTrue("ntpdatecommand called", mockResults.ntpDateCommandCalled);
        assertTrue("ntpqcommand called", mockResults.ntpQCommandCalled);
    }

    /**
     * Tests that based on the NTPDateResult the current time state is selected.
     * @throws java.lang.Exception
     */
    @Test
    public void testTimeTask() throws Exception {
        LOG.info("timeTasks");

        TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(TimeMonitorAppConfigTest.getAppProperties());
        final List<String> errors = new LinkedList<>();
        TimeMonitorRuntimeConfig runConfig = TimeMonitorRuntimeConfig.load(getRunProperties(), errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }

        // Offset: 0 < 995: INSYNC
        TimeMonitorRunnable instance = new TimeMonitorRunnable(appConfig, runConfig);
        TimeState actual = instance.timeTask(new NTPDateResult(0, null, "server3", 2, 0.0, 0.0, false), false);
        assertEquals(TimeState.INSYNC, actual);
        // Offset: abs(-441) < 995: INSYNC
        instance = new TimeMonitorRunnable(appConfig, runConfig);
        actual = instance.timeTask(new NTPDateResult(0, null, "server3", 2, -0.441, 3.0, false), false);
        assertEquals(TimeState.INSYNC, actual);
        // Offset: 441 < 995: INSYNC
        instance = new TimeMonitorRunnable(appConfig, runConfig);
        actual = instance.timeTask(new NTPDateResult(0, null, "server3", 2, 0.441, 3.0, false), false);
        assertEquals(TimeState.INSYNC, actual);
        // Offset: 995 <= 995: SOON_OUT_OF_SYNC
        instance = new TimeMonitorRunnable(appConfig, runConfig);
        actual = instance.timeTask(new NTPDateResult(0, null, "server3", 2, 0.995, 3.0, false), false);
        assertEquals(TimeState.SOON_OUT_OF_SYNC, actual);

        // Offset: 5000 > 995: OUT_OF_SYNC
        instance = new TimeMonitorRunnable(appConfig, runConfig);
        actual = instance.timeTask(new NTPDateResult(0, null, "server3", 2, 5.0, 0.0, false), false);
        assertEquals(TimeState.OUT_OF_SYNC, actual);
        // Offset: inf > 995: OUT_OF_SYNC
        instance = new TimeMonitorRunnable(appConfig, runConfig);
        actual = instance.timeTask(new NTPDateResult(0, null, "server3", 2, Double.POSITIVE_INFINITY, 0.0, false), false);
        assertEquals(TimeState.OUT_OF_SYNC, actual);
        // Offset: abs(-inf) > 995: OUT_OF_SYNC
        instance = new TimeMonitorRunnable(appConfig, runConfig);
        actual = instance.timeTask(new NTPDateResult(0, null, "server3", 2, Double.NEGATIVE_INFINITY, 0.0, false), false);
        assertEquals(TimeState.OUT_OF_SYNC, actual);
        // Offset: 996 > 995: OUT_OF_SYNC
        instance = new TimeMonitorRunnable(appConfig, runConfig);
        actual = instance.timeTask(new NTPDateResult(0, null, "server3", 2, 0.996, 0.0, false), false);
        assertEquals(TimeState.OUT_OF_SYNC, actual);

        // Offset: 800 > 703 : SOON_OUT_OF_SYNC
        instance = new TimeMonitorRunnable(appConfig, runConfig);
        actual = instance.timeTask(new NTPDateResult(0, null, "server3", 2, 0.8, 0.0, false), false);
        assertEquals(TimeState.SOON_OUT_OF_SYNC, actual);

        // exitCode: non-zero
        instance = new TimeMonitorRunnable(appConfig, runConfig);
        actual = instance.timeTask(new NTPDateResult(1, null, "server3", 2, Double.NaN, 0.0, false), false);
        assertEquals(TimeState.UNKNOWN, actual);
        instance = new TimeMonitorRunnable(appConfig, runConfig);
        actual = instance.timeTask(new NTPDateResult(-1, null, "server3", -13, Double.NaN, -1.0, false), false);
        assertEquals(TimeState.UNKNOWN, actual);

        // no results
        instance = new TimeMonitorRunnable(appConfig, runConfig);
        actual = instance.timeTask(null, false);
        assertEquals(TimeState.UNKNOWN, actual);
    }

    @Test
    public void testTimeTask_stratum0() throws Exception {
        LOG.info("timeTasks_stratum0");

        TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(TimeMonitorAppConfigTest.getAppProperties());
        final List<String> errors = new LinkedList<>();
        TimeMonitorRuntimeConfig runConfig = TimeMonitorRuntimeConfig.load(getRunProperties(), errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }

        // stratum=0
        TimeMonitorRunnable instance = new TimeMonitorRunnable(appConfig, runConfig);
        final int STRATUM_ZERO = 0;
        TimeState actual = instance.timeTask(new NTPDateResult(0, null, "server3", STRATUM_ZERO, 0.0, 0.0, false), false);
        assertEquals(TimeState.UNKNOWN, actual);
    }

    /**
     * Tests the leap state transformation algorithm
     * @throws Exception
     */
    @Test
    public void testLeapState() throws Exception {
        TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(TimeMonitorAppConfigTest.getAppProperties());
        final List<String> errors = new LinkedList<>();
        TimeMonitorRuntimeConfig runConfig = TimeMonitorRuntimeConfig.load(getRunProperties(), errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }
        TimeMonitorRunnable instance = new TimeMonitorRunnable(appConfig, runConfig);

        // test that changing POSITIVE -> NONE works when time is well after a leap second
        LeapState state = instance.calculateLeapStateTransition(getDate(2013, 1, 1, 0, 1, 1), LeapState.POSITIVE, LeapState.NONE);
        assertEquals("Leap state", LeapState.NONE, state);

        // test that changing POSITIVE -> NONE exactly at 00:00:00 leaves state at POSITIVE to be on the safe side
        state = instance.calculateLeapStateTransition(getDate(2013, 1, 1, 0, 0, 0), LeapState.POSITIVE, LeapState.NONE);
        assertEquals("Leap state", LeapState.POSITIVE, state);

        // like above but with NEGATIVE
        state = instance.calculateLeapStateTransition(getDate(2013, 1, 1, 0, 0, 0), LeapState.NEGATIVE, LeapState.NONE);
        assertEquals("Leap state", LeapState.NEGATIVE, state);

        // transition at 23:59:59 (when the positive leap second happens)
        state = instance.calculateLeapStateTransition(getDate(2012, 12, 31, 23, 59, 58), LeapState.POSITIVE, LeapState.NONE);
        assertEquals("Leap state", LeapState.POSITIVE, state);
    }

    private Date getDate(int year, int month, int day, int h, int m, int s) {
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));

        cal.set(Calendar.YEAR, year);
        cal.set(Calendar.MONTH, month - 1);
        cal.set(Calendar.DAY_OF_MONTH, day);
        cal.set(Calendar.HOUR_OF_DAY, h);
        cal.set(Calendar.MINUTE, m);
        cal.set(Calendar.SECOND, s);
        cal.set(Calendar.MILLISECOND, 0);

        return cal.getTime();
    }

    /**
     * Tests that based on the NTPDateResult the current time state is selected.
     * @throws java.lang.Exception
     */
    @Test
    public void testReportTask() throws Exception {
        LOG.info("reportTask");

        TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(TimeMonitorAppConfigTest.getAppProperties());
        final List<String> errors = new LinkedList<>();
        TimeMonitorRuntimeConfig runConfig = TimeMonitorRuntimeConfig.load(getRunProperties(), errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }

        final MockResults mockResults = new MockResults();
        TimeMonitorRunnable instance = new TimeMonitorRunnable(appConfig, runConfig) {
            @Override
            protected void reportInSync(boolean insync, LeapState leapState,
                    long expiration, long leapExpiration, long stateExpiration) throws UnsupportedEncodingException, MalformedURLException, IOException {
                mockResults.reportInSyncCalled = true;
                mockResults.reportInSync = insync;
                mockResults.reportLeapState = leapState;
                mockResults.reportExpiration = expiration;
                mockResults.reportLeapExpiration = leapExpiration;
            }
        };

        // Test with INSYNC => INSYNC=true
        long currentTime = 1351873186508L;
        instance.reportTask(TimeState.INSYNC, LeapState.NONE, currentTime);
        assertTrue("reportInSync called", mockResults.reportInSyncCalled);
        assertEquals(true, mockResults.reportInSync);
        assertEquals(currentTime + runConfig.getStatusExpireTime(), mockResults.reportExpiration);
        assertEquals(currentTime + runConfig.getLeapStatusExpireTime(), mockResults.reportLeapExpiration);
        mockResults.reset();

        // Test with UNKNOWN => INSYNC=false, expiration=0
        currentTime = 1351873186509L;
        instance.reportTask(TimeState.UNKNOWN, LeapState.NONE, currentTime);
        assertTrue("reportInSync called", mockResults.reportInSyncCalled);
        assertEquals(false, mockResults.reportInSync);
        assertEquals(0, mockResults.reportExpiration);
        assertEquals(currentTime + runConfig.getLeapStatusExpireTime(), mockResults.reportLeapExpiration);
        mockResults.reset();

        // Test with SOON_OUT_OF_SYNC => INSYNC=true
        currentTime = 1351873186510L;
        instance.reportTask(TimeState.SOON_OUT_OF_SYNC, LeapState.NONE, currentTime);
        assertTrue("reportInSync called", mockResults.reportInSyncCalled);
        assertEquals(true, mockResults.reportInSync);
        assertEquals(currentTime + runConfig.getStatusExpireTime(), mockResults.reportExpiration);
        assertEquals(currentTime + runConfig.getLeapStatusExpireTime(), mockResults.reportLeapExpiration);
        mockResults.reset();

        // Test with OUT_OF_SYNC => INSYNC=false, expiration=0
        currentTime = 1351873186511L;
        instance.reportTask(TimeState.OUT_OF_SYNC, LeapState.NONE, currentTime);
        assertTrue("reportInSync called", mockResults.reportInSyncCalled);
        assertEquals(false, mockResults.reportInSync);
        assertEquals(0, mockResults.reportExpiration);
        assertEquals(currentTime + runConfig.getLeapStatusExpireTime(), mockResults.reportLeapExpiration);
        mockResults.reset();
    }
    
    /**
     * Test that a second call doesn't query the server if a previous call
     * gave a kiss-of-death response.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testRunRoundCallsTasksKoD() throws Exception {
        LOG.info("runRoundCallsTasks");

        TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(TimeMonitorAppConfigTest.getAppProperties());
        final List<String> errors = new LinkedList<>();
        TimeMonitorRuntimeConfig runConfig = TimeMonitorRuntimeConfig.load(getRunProperties(), errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }
        final MockResults mockResults = new MockResults();
        MockTimeMonitorRunnable instance = new MockTimeMonitorRunnable(appConfig, runConfig) {

            @Override
            protected NTPDateResult queryTask() {
                mockResults.queryTaskCalled = true;
                
                return new NTPDateResult(0, "127.0.0.1 rate limit response from server.",
                        "server1", 1, 0.01, 0.02, true);
            }

            @Override
            protected NTPQResult leapSecondQueryTask() {
                mockResults.leapSecondQueryTaskCalled = true;
                return new NTPQResult(0, null, LeapState.NONE);
            }

            @Override
            protected TimeState timeTask(NTPDateResult ntpDate, boolean forceLogging) {
                mockResults.timeTaskCalled = true;
                return super.timeTask(ntpDate, forceLogging);
            }

            @Override
            protected ReportState reportTask(TimeState timeState, LeapState leapState, long currentTime) {
                mockResults.reportTaskCalled = true;
                return ReportState.REPORTED;
            }

        };
        
        // first run should set the flag to stop calling out to query the server
        instance.runRound();
        mockResults.reset();
        instance.runRound();

        assertFalse("query task called", mockResults.queryTaskCalled);
        assertFalse("leap second query task called", mockResults.leapSecondQueryTaskCalled);
    }

    public static Properties getRunProperties() {
        return runProperties;
    }

    private static class MockResults {
        private boolean queryTaskCalled;
        private boolean leapSecondQueryTaskCalled;
        private boolean timeTaskCalled;
        private boolean reportTaskCalled;
        private boolean ntpDateCommandCalled;
        private boolean ntpQCommandCalled;
        private boolean reportInSyncCalled;
        private boolean reportInSync;
        private LeapState reportLeapState;
        private long reportExpiration;
        private long reportLeapExpiration;
        private String requestBody;

        public void reset() {
            queryTaskCalled = false;
            leapSecondQueryTaskCalled = false;
            timeTaskCalled = false;
            reportTaskCalled = false;
            ntpDateCommandCalled = false;
            ntpQCommandCalled = false;
            reportInSyncCalled = false;
            reportInSync = false;
            reportExpiration = 0;
        }
    }

    private static class MockStateHolder  {

        private TimeState timeState;
        private ReportState reportState;
        private LeapState leapState;
        private long lastUpdated;

        public TimeState getTimeState() {
            return timeState;
        }

        public ReportState getReportState() {
            return reportState;
        }

        public LeapState getLeapState() {
            return leapState;
        }

        public long getLastUpdated() {
            return lastUpdated;
        }

    }

    private static class MockTimeMonitorRunnable extends TimeMonitorRunnable {

        private static final long DISABLED_MIN_RUNTIME = 100;

        private TimeMonitorAppConfig appConfig;
        private TimeMonitorRuntimeConfig runConfig;

        public MockTimeMonitorRunnable(TimeMonitorAppConfig appConfig, TimeMonitorRuntimeConfig runConfig) {
            super(appConfig, runConfig, createNTPDateCommand(appConfig, runConfig), createNTPQCommand(appConfig, runConfig), DISABLED_MIN_RUNTIME);
            this.appConfig = appConfig;
            this.runConfig = runConfig;
        }

        public MockTimeMonitorRunnable(TimeMonitorAppConfig appConfig, TimeMonitorRuntimeConfig runConfig, NTPQCommand ntpqCommand) {
            super(appConfig, runConfig, createNTPDateCommand(appConfig, runConfig), ntpqCommand, DISABLED_MIN_RUNTIME);
            this.appConfig = appConfig;
            this.runConfig = runConfig;
        }

        private static NTPDateCommand createNTPDateCommand(TimeMonitorAppConfig appConfig, TimeMonitorRuntimeConfig runConfig) {
            return new MockNTPDateCommand(appConfig.getTimeServerNtpdateCommand(), runConfig.getTimeServerHost(), runConfig.getTimeServerSendSamples(), runConfig.getTimeServerTimeout());
        }

        private static NTPQCommand createNTPQCommand(TimeMonitorAppConfig appConfig, TimeMonitorRuntimeConfig runConfig) {
            return new MockNTPQDateCommand(appConfig.getTimeServerNtpqCommand());
        }

        @Override
        protected NTPDateCommand createNTPDateCommand() {
            return createNTPDateCommand(appConfig, runConfig);
        }

    }

    private static class MockNTPDateCommand extends NTPDateCommand {

        public MockNTPDateCommand(String executable, String host) {
            super(executable, host);
        }

        public MockNTPDateCommand(String executable, String hosts, Integer samples, Double timeout) {
            super(executable, hosts, samples, timeout);
        }

        @Override
        public AbstractResult execute() throws IOException {
            parser = new NTPDateParser();
            List<String> lines = new LinkedList<>();
            lines.add("server 192.168.30.25, stratum 1, offset 0.092352, delay 0.08981");
            lines.add("28 Aug 10:55:51 ntpdate[5961]: step time server 192.168.30.25 offset 0.092352 sec");
            String error = "";
            int exitValue = 0;
            return parser.parse(exitValue, error, lines);
        }

    }

    private static class MockNTPQDateCommand extends NTPQCommand {

        private boolean called;

        public MockNTPQDateCommand(String executable) {
            super(executable, 0);
        }

        @Override
        public AbstractResult execute() throws IOException {
            return new NTPQResult(0, "Mocked test", LeapState.NONE);
        }

        public boolean isCalled() {
            return called;
        }

    }

}
