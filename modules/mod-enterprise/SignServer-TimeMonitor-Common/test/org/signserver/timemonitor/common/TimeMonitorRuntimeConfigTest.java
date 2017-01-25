/**
 * ***********************************************************************
 *                                                                       *
 * SignServer: The OpenSource Automated Signing Server * * This software is free
 * software; you can redistribute it and/or * modify it under the terms of the
 * GNU Lesser General Public * License as published by the Free Software
 * Foundation; either * version 2.1 of the License, or any later version. * *
 * See terms of license at gnu.org. * *
 ************************************************************************
 */
package org.signserver.timemonitor.common;

import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Properties;
import java.util.Set;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import static org.signserver.timemonitor.common.TimeMonitorRuntimeConfig.PROPERTY_LEAPSTATUS_EXPIRE_TIME;
import static org.signserver.timemonitor.common.TimeMonitorRuntimeConfig.PROPERTY_MAX_ACCEPTED_OFFSET;
import static org.signserver.timemonitor.common.TimeMonitorRuntimeConfig.PROPERTY_MIN_RUN_TIME;
import static org.signserver.timemonitor.common.TimeMonitorRuntimeConfig.PROPERTY_STATUS_EXPIRE_TIME;
import static org.signserver.timemonitor.common.TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_HOST;
import static org.signserver.timemonitor.common.TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_SENDSAMPLES;
import static org.signserver.timemonitor.common.TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_TIMEOUT;
import static org.signserver.timemonitor.common.TimeMonitorRuntimeConfig.PROPERTY_WARN_OFFSET;
import static org.signserver.timemonitor.common.TimeMonitorRuntimeConfig.PROPERTY_WARN_RUN_TIME;

/**
 * Tests for the TimeMonitorConfig class.
 *
 * @author Markus Kilås
 * @version $Id: TimeMonitorConfigTest.java 4568 2012-12-10 13:46:03Z marcus $
 */
public class TimeMonitorRuntimeConfigTest extends TestCase {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(TimeMonitorRuntimeConfigTest.class);

    private static final Properties runProperties1;
    private static final String PROP_HOST1 = "192.168.10.200";
    private static final int PROP_SENDSAMPLES1 = 4;
    private static final double PROP_TIMEOUT1 = 0.3;
    private static final int PROP_MAX_ACCEPTED_OFFSET1 = 995;
    private static final int PROP_WARN_OFFSET1 = 498;
    private static final int PROP_STATUS_EXPIRE_TIME1 = 901;
    private static final int PROP_LEAPSTATUS_EXPIRE_TIME1 = 60000;
    private static final int PROP_MIN_RUN_TIME1 = 501;
    private static final int PROP_WARN_RUN_TIME1 = 703;
    private static final boolean PROP_DISABLED1 = false;

    private static final Properties runProperties2;
    private static final String PROP_HOST2 = "192.168.10.201";
    private static final int PROP_SENDSAMPLES2 = 2;
    private static final double PROP_TIMEOUT2 = 0.4;
    private static final int PROP_MAX_ACCEPTED_OFFSET2 = 992;
    private static final int PROP_WARN_OFFSET2 = 492;
    private static final int PROP_STATUS_EXPIRE_TIME2 = 902;
    private static final int PROP_LEAPSTATUS_EXPIRE_TIME2 = 60002;
    private static final int PROP_MIN_RUN_TIME2 = 502;
    private static final int PROP_WARN_RUN_TIME2 = 704;
    private static final boolean PROP_DISABLED2 = true;

    private static final Set<String> REQUIRED_PROPERTY_NAMES = Collections.unmodifiableSet(new HashSet<String>(
            Arrays.asList(
                PROPERTY_TIMESERVER_HOST,
                PROPERTY_TIMESERVER_SENDSAMPLES,
                PROPERTY_TIMESERVER_TIMEOUT,
                PROPERTY_MAX_ACCEPTED_OFFSET,
                PROPERTY_WARN_OFFSET,
                PROPERTY_STATUS_EXPIRE_TIME,
                PROPERTY_LEAPSTATUS_EXPIRE_TIME,
                PROPERTY_MIN_RUN_TIME,
                PROPERTY_WARN_RUN_TIME
            )));

    static {
        // Some useful sample properties
        runProperties1 = new Properties();
        runProperties1.setProperty(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_HOST, PROP_HOST1);
        runProperties1.setProperty(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_SENDSAMPLES, String.valueOf(PROP_SENDSAMPLES1));
        runProperties1.setProperty(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_TIMEOUT, String.valueOf(PROP_TIMEOUT1));
        runProperties1.setProperty(TimeMonitorRuntimeConfig.PROPERTY_MAX_ACCEPTED_OFFSET, String.valueOf(PROP_MAX_ACCEPTED_OFFSET1));
        runProperties1.setProperty(TimeMonitorRuntimeConfig.PROPERTY_WARN_OFFSET, String.valueOf(PROP_WARN_OFFSET1));
        runProperties1.setProperty(TimeMonitorRuntimeConfig.PROPERTY_STATUS_EXPIRE_TIME, String.valueOf(PROP_STATUS_EXPIRE_TIME1));
        runProperties1.setProperty(TimeMonitorRuntimeConfig.PROPERTY_LEAPSTATUS_EXPIRE_TIME, String.valueOf(PROP_LEAPSTATUS_EXPIRE_TIME1));
        runProperties1.setProperty(TimeMonitorRuntimeConfig.PROPERTY_MIN_RUN_TIME, String.valueOf(PROP_MIN_RUN_TIME1));
        runProperties1.setProperty(TimeMonitorRuntimeConfig.PROPERTY_WARN_RUN_TIME, String.valueOf(PROP_WARN_RUN_TIME1));
        runProperties1.setProperty(TimeMonitorRuntimeConfig.PROPERTY_DISABLED, String.valueOf(PROP_DISABLED1));

        // Some properties were all are different than runProperties1
        runProperties2 = new Properties();
        runProperties2.setProperty(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_HOST, PROP_HOST2);
        runProperties2.setProperty(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_SENDSAMPLES, String.valueOf(PROP_SENDSAMPLES2));
        runProperties2.setProperty(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_TIMEOUT, String.valueOf(PROP_TIMEOUT2));
        runProperties2.setProperty(TimeMonitorRuntimeConfig.PROPERTY_MAX_ACCEPTED_OFFSET, String.valueOf(PROP_MAX_ACCEPTED_OFFSET2));
        runProperties2.setProperty(TimeMonitorRuntimeConfig.PROPERTY_WARN_OFFSET, String.valueOf(PROP_WARN_OFFSET2));
        runProperties2.setProperty(TimeMonitorRuntimeConfig.PROPERTY_STATUS_EXPIRE_TIME, String.valueOf(PROP_STATUS_EXPIRE_TIME2));
        runProperties2.setProperty(TimeMonitorRuntimeConfig.PROPERTY_LEAPSTATUS_EXPIRE_TIME, String.valueOf(PROP_LEAPSTATUS_EXPIRE_TIME2));
        runProperties2.setProperty(TimeMonitorRuntimeConfig.PROPERTY_MIN_RUN_TIME, String.valueOf(PROP_MIN_RUN_TIME2));
        runProperties2.setProperty(TimeMonitorRuntimeConfig.PROPERTY_WARN_RUN_TIME, String.valueOf(PROP_WARN_RUN_TIME2));
        runProperties2.setProperty(TimeMonitorRuntimeConfig.PROPERTY_DISABLED, String.valueOf(PROP_DISABLED2));
    }

    public static Properties getRunProperties() {
        return runProperties1;
    }

    public TimeMonitorRuntimeConfigTest(String testName) throws MalformedURLException, UnknownHostException {
        super(testName);
    }

    @Override
    protected void setUp() throws Exception {

    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test of getTimeServerHost method, of class TimeMonitorConfig.
     *
     * @throws java.lang.Exception
     */
    public void testGetters() throws Exception {
        LOG.info("getters");

        LinkedList<String> errors = new LinkedList<String>();
        TimeMonitorRuntimeConfig runConfig = TimeMonitorRuntimeConfig.load(runProperties1, errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }

        assertEquals(PROP_MAX_ACCEPTED_OFFSET1, runConfig.getMaxAcceptedOffset());
        assertEquals(PROP_MIN_RUN_TIME1, runConfig.getMinRunTime());
        assertEquals(PROP_STATUS_EXPIRE_TIME1, runConfig.getStatusExpireTime());
        assertEquals(PROP_HOST1, runConfig.getTimeServerHost());
        assertEquals(PROP_SENDSAMPLES1, runConfig.getTimeServerSendSamples());
        assertEquals(PROP_TIMEOUT1, runConfig.getTimeServerTimeout());
        assertEquals(PROP_WARN_OFFSET1, runConfig.getWarnOffset());
        assertEquals(PROP_WARN_RUN_TIME1, runConfig.getWarnRunTime());
        assertEquals(PROP_LEAPSTATUS_EXPIRE_TIME1, runConfig.getLeapStatusExpireTime());
        assertTrue("conf loaded with 'load' should be original", runConfig.isOriginal());
        assertFalse("disabled", runConfig.isDisabled());
    }

    /**
     * Tests disabled property.
     * @throws Exception
     */
    public void testDisabledProperty() throws Exception {
        LinkedList<String> errors = new LinkedList<String>();
        TimeMonitorRuntimeConfig firstConfig = TimeMonitorRuntimeConfig.load(runProperties1, errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }

        Properties props = new Properties();
        props.putAll(runProperties1);
        props.setProperty(TimeMonitorRuntimeConfig.PROPERTY_DISABLED, String.valueOf(true));
        TimeMonitorRuntimeConfig runConfig = firstConfig.update(props, "222", errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }

        assertTrue("disabled", runConfig.isDisabled());
    }

    /**
     * Tests disabled property default value.
     * @throws Exception
     */
    public void testDisabledPropertyOptional() throws Exception {
        LinkedList<String> errors = new LinkedList<String>();
        Properties props = new Properties();
        props.putAll(runProperties1);
        props.remove(TimeMonitorRuntimeConfig.PROPERTY_DISABLED);
        TimeMonitorRuntimeConfig runConfig = TimeMonitorRuntimeConfig.load(props, errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }

        assertTrue("conf loaded with 'load' should be original", runConfig.isOriginal());
        assertFalse("disabled", runConfig.isDisabled());
    }

    /**
     * Test of load method, of class TimeMonitorConfig.
     */
    public void testLoad() {
        LOG.info("load");

        // Test loading ok
        LinkedList<String> errors = new LinkedList<String>();
        TimeMonitorRuntimeConfig.load(runProperties1, errors);
        if (!errors.isEmpty()) {
            fail("Failed: " + errors.toString());
        }

        // Test missing and incorrect properties
        requireRunPropertyLoadTest(TimeMonitorRuntimeConfig.PROPERTY_MAX_ACCEPTED_OFFSET);
        illegalRunPropertyValueLoadTest(TimeMonitorRuntimeConfig.PROPERTY_MAX_ACCEPTED_OFFSET, "not-a-double");
        requireRunPropertyLoadTest(TimeMonitorRuntimeConfig.PROPERTY_MIN_RUN_TIME);
        illegalRunPropertyValueLoadTest(TimeMonitorRuntimeConfig.PROPERTY_MIN_RUN_TIME, "not-an-integer");
        requireRunPropertyLoadTest(TimeMonitorRuntimeConfig.PROPERTY_STATUS_EXPIRE_TIME);
        illegalRunPropertyValueLoadTest(TimeMonitorRuntimeConfig.PROPERTY_STATUS_EXPIRE_TIME, "not-an-integer");
        requireRunPropertyLoadTest(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_HOST);
        requireRunPropertyLoadTest(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_SENDSAMPLES);
        illegalRunPropertyValueLoadTest(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_SENDSAMPLES, "not-an-integer");
        requireRunPropertyLoadTest(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_TIMEOUT);
        illegalRunPropertyValueLoadTest(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_TIMEOUT, "not-an-integer");
        requireRunPropertyLoadTest(TimeMonitorRuntimeConfig.PROPERTY_WARN_OFFSET);
        illegalRunPropertyValueLoadTest(TimeMonitorRuntimeConfig.PROPERTY_WARN_OFFSET, "not-a-double");
        requireRunPropertyLoadTest(TimeMonitorRuntimeConfig.PROPERTY_WARN_RUN_TIME);
        illegalRunPropertyValueLoadTest(TimeMonitorRuntimeConfig.PROPERTY_WARN_RUN_TIME, "not-an-integer");
        requireRunPropertyLoadTest(TimeMonitorRuntimeConfig.PROPERTY_LEAPSTATUS_EXPIRE_TIME);
        illegalRunPropertyValueLoadTest(TimeMonitorRuntimeConfig.PROPERTY_LEAPSTATUS_EXPIRE_TIME, "non-an-integer");
    }

    /**
     * Tests the update method.
     * @throws Exception
     */
    public void testUpdate() throws Exception {
        LinkedList<String> errors = new LinkedList<String>();
        TimeMonitorRuntimeConfig firstRunConfig = TimeMonitorRuntimeConfig.load(runProperties1, errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }
        final String newVersion = "1111338";

        TimeMonitorRuntimeConfig runConfig = firstRunConfig.update(runProperties2, newVersion, errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }

        // All fields except 'original', 'disabled' and 'version' should be the same
        assertEquals(PROP_MAX_ACCEPTED_OFFSET2, runConfig.getMaxAcceptedOffset());
        assertEquals(PROP_MIN_RUN_TIME2, runConfig.getMinRunTime());
        assertEquals(PROP_STATUS_EXPIRE_TIME2, runConfig.getStatusExpireTime());
        assertEquals(PROP_HOST2, runConfig.getTimeServerHost());
        assertEquals(PROP_SENDSAMPLES2, runConfig.getTimeServerSendSamples());
        assertEquals(PROP_TIMEOUT2, runConfig.getTimeServerTimeout());
        assertEquals(PROP_WARN_OFFSET2, runConfig.getWarnOffset());
        assertEquals(PROP_WARN_RUN_TIME2, runConfig.getWarnRunTime());
        assertEquals(PROP_LEAPSTATUS_EXPIRE_TIME2, runConfig.getLeapStatusExpireTime());
        assertTrue("disabled", runConfig.isDisabled());
        assertFalse("conf updated should not be original", runConfig.isOriginal());
        assertEquals(newVersion, runConfig.getVersion());

        // Test missing and incorrect properties
        requireRunPropertyUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_MAX_ACCEPTED_OFFSET);
        illegalRunPropertyValueUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_MAX_ACCEPTED_OFFSET, "not-a-double");
        requireRunPropertyUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_MIN_RUN_TIME);
        illegalRunPropertyValueUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_MIN_RUN_TIME, "not-an-integer");
        requireRunPropertyUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_STATUS_EXPIRE_TIME);
        illegalRunPropertyValueUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_STATUS_EXPIRE_TIME, "not-an-integer");
        requireRunPropertyUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_HOST);
        requireRunPropertyUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_SENDSAMPLES);
        illegalRunPropertyValueUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_SENDSAMPLES, "not-an-integer");
        requireRunPropertyUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_TIMEOUT);
        illegalRunPropertyValueUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_TIMEOUT, "not-an-integer");
        requireRunPropertyUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_WARN_OFFSET);
        illegalRunPropertyValueUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_WARN_OFFSET, "not-a-double");
        requireRunPropertyUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_WARN_RUN_TIME);
        illegalRunPropertyValueUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_WARN_RUN_TIME, "not-an-integer");
        requireRunPropertyUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_LEAPSTATUS_EXPIRE_TIME);
        illegalRunPropertyValueUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_LEAPSTATUS_EXPIRE_TIME, "non-an-integer");
        illegalRunPropertyValueUpdateTest(TimeMonitorRuntimeConfig.PROPERTY_DISABLED, "non-an-boolean");
    }

    /**
     * Tests the disable method.
     * @throws Exception
     */
    public void testDisable() throws Exception {
        LinkedList<String> errors = new LinkedList<String>();
        TimeMonitorRuntimeConfig firstRunConfig = TimeMonitorRuntimeConfig.load(runProperties1, errors);
        if (!errors.isEmpty()) {
            throw new Exception("Error in test config: " + errors.toString());
        }
        final String newVersion = "1111337";

        TimeMonitorRuntimeConfig runConfig = firstRunConfig.disable(newVersion);

        // All fields except 'original', 'disabled' and 'version' should be the same
        assertEquals(PROP_MAX_ACCEPTED_OFFSET1, runConfig.getMaxAcceptedOffset());
        assertEquals(PROP_MIN_RUN_TIME1, runConfig.getMinRunTime());
        assertEquals(PROP_STATUS_EXPIRE_TIME1, runConfig.getStatusExpireTime());
        assertEquals(PROP_HOST1, runConfig.getTimeServerHost());
        assertEquals(PROP_SENDSAMPLES1, runConfig.getTimeServerSendSamples());
        assertEquals(PROP_TIMEOUT1, runConfig.getTimeServerTimeout());
        assertEquals(PROP_WARN_OFFSET1, runConfig.getWarnOffset());
        assertEquals(PROP_WARN_RUN_TIME1, runConfig.getWarnRunTime());
        assertEquals(PROP_LEAPSTATUS_EXPIRE_TIME1, runConfig.getLeapStatusExpireTime());
        assertFalse("conf updated should not be original", runConfig.isOriginal());
        assertTrue("disabled", runConfig.isDisabled());
        assertEquals(newVersion, runConfig.getVersion());
    }

    /**
     * Tests the getPropertyNames method.
     * @throws Exception
     */
    public void testGetPropertyNames() throws Exception {
        assertEquals(REQUIRED_PROPERTY_NAMES, TimeMonitorRuntimeConfig.getPropertyNames());
    }

    private void requireRunPropertyLoadTest(final String propertyName) {
        Properties props = new Properties();
        props.putAll(runProperties1);
        props.remove(propertyName);
        LinkedList<String> errors = new LinkedList<String>();
        TimeMonitorRuntimeConfig.load(props, errors);
        if (!errors.toString().contains(propertyName)) {
            fail("Should have failed");
        }
    }

    private void illegalRunPropertyValueLoadTest(final String propertyName, final String illegalValue) {
        Properties props = new Properties();
        props.putAll(runProperties1);
        props.setProperty(propertyName, illegalValue);
        LinkedList<String> errors = new LinkedList<String>();
        TimeMonitorRuntimeConfig.load(props, errors);
        if (!errors.toString().contains(propertyName)) {
            fail("Should have failed");
        }
    }
    
    private void requireRunPropertyUpdateTest(final String propertyName) {
        Properties props = new Properties();
        props.putAll(runProperties1);
        props.remove(propertyName);
        LinkedList<String> errors = new LinkedList<String>();
        new TimeMonitorRuntimeConfig().update(props, "20", errors);
        if (!errors.toString().contains(propertyName)) {
            fail("Should have failed");
        }
    }

    private void illegalRunPropertyValueUpdateTest(final String propertyName, final String illegalValue) {
        Properties props = new Properties();
        props.putAll(runProperties1);
        props.setProperty(propertyName, illegalValue);
        LinkedList<String> errors = new LinkedList<String>();
        new TimeMonitorRuntimeConfig().update(props, "21", errors);
        if (!errors.toString().contains(propertyName)) {
            fail("Should have failed");
        }
    }

}
