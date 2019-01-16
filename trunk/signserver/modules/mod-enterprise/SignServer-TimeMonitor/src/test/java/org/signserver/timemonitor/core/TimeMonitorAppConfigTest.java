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
package org.signserver.timemonitor.core;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Properties;
import junit.framework.TestCase;
import org.apache.log4j.Logger;

/**
 * Tests for the TimeMonitorConfig class.
 *
 * @author Markus Kilås
 * @version $Id: TimeMonitorConfigTest.java 4568 2012-12-10 13:46:03Z marcus $
 */
public class TimeMonitorAppConfigTest extends TestCase {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(TimeMonitorAppConfigTest.class);

    private static final Properties appProperties;
    private static final String PROP_NTPDATE = "/usr/sbin/nptdate";
    private static final String PROP_NTPQ = "/usr/bin/ntpq";
    private static final boolean PROP_ENABLED = true;
    private final InetAddress PROP_BINDADDRESS = InetAddress.getByName("127.0.0.1");
    private static final int PROP_PORT = 8980;
    private static final int PROP_THREADS = 5;
    private static final int PROP_BACKLOG = 1;
    private final URL PROP_URL = new URL("http://localhost:8080/signserver/process");
    private static final String PROP_WORKERNAME = "StatusPropertiesWorker";
    private static final String PROP_PROPERTY_NAME = "TIMESOURCE0_INSYNC";
    private static final String PROP_LEAPPROPERTY_NAME = "LEAPSECOND";

    static {
        appProperties = new Properties();
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_TIMESERVER_NTPDATECOMMAND, PROP_NTPDATE);
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_TIMESERVER_NTPQCOMMAND, PROP_NTPQ);
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_STATEWEB_ENABLED, String.valueOf(PROP_ENABLED));
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_STATEWEB_BINDADDRESS, "127.0.0.1");
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_STATEWEB_PORT, String.valueOf(PROP_PORT));
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_STATEWEB_THREADS, String.valueOf(PROP_THREADS));
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_STATEWEB_BACKLOG, String.valueOf(PROP_BACKLOG));

        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_PROCESS_URL, "http://localhost:8080/signserver/process");
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_STATUSPROPERTIESWORKER_NAME, PROP_WORKERNAME);
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_STATUSPROPERTY_NAME, PROP_PROPERTY_NAME);
        appProperties.setProperty(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_LEAPSTATUSPROPERTY_NAME, PROP_LEAPPROPERTY_NAME);
    }

    public static Properties getAppProperties() {
        return appProperties;
    }

    public TimeMonitorAppConfigTest(String testName) throws MalformedURLException, UnknownHostException {
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

        TimeMonitorAppConfig appConfig = TimeMonitorAppConfig.load(appProperties);

        assertEquals(appConfig.getTimeServerNtpdateCommand(), PROP_NTPDATE);
        assertEquals(appConfig.getSignServerProcessUrl(), PROP_URL);
        assertEquals(appConfig.getSignServerStatusPropertiesWorkerName(), PROP_WORKERNAME);
        assertEquals(appConfig.getSignServerStatusPropertyName(), PROP_PROPERTY_NAME);
        assertEquals(appConfig.getStatuswebBacklog(), PROP_BACKLOG);
        assertEquals(appConfig.getStatuswebBindAddress(), PROP_BINDADDRESS);
        assertEquals(appConfig.getStatuswebPort(), PROP_PORT);
        assertEquals(appConfig.getStatuswebThreads(), PROP_THREADS);
        assertEquals(appConfig.isStatuswebEnabled(), PROP_ENABLED);
        assertEquals(appConfig.getTimeServerNtpqCommand(), PROP_NTPQ);
        assertEquals(appConfig.getSignServerLeapStatusPropertyName(), PROP_LEAPPROPERTY_NAME);
    }

    /**
     * Test of load method, of class TimeMonitorConfig.
     */
    public void testLoad() {
        LOG.info("load");

        // Test missing property
        requireAppPropertyTest(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_PROCESS_URL);
        requireAppPropertyTest(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_STATUSPROPERTIESWORKER_NAME);
        requireAppPropertyTest(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_STATUSPROPERTY_NAME);
        requireAppPropertyTest(TimeMonitorAppConfig.PROPERTY_STATEWEB_BACKLOG);
        illegalAppPropertyValueTest(TimeMonitorAppConfig.PROPERTY_STATEWEB_BACKLOG, "not-an-integer");
        requireAppPropertyTest(TimeMonitorAppConfig.PROPERTY_STATEWEB_BINDADDRESS);
        requireAppPropertyTest(TimeMonitorAppConfig.PROPERTY_STATEWEB_ENABLED);
        illegalAppPropertyValueTest(TimeMonitorAppConfig.PROPERTY_STATEWEB_ENABLED, "not-a-boolean");
        requireAppPropertyTest(TimeMonitorAppConfig.PROPERTY_STATEWEB_PORT);
        illegalAppPropertyValueTest(TimeMonitorAppConfig.PROPERTY_STATEWEB_PORT, "not-an-integer");
        requireAppPropertyTest(TimeMonitorAppConfig.PROPERTY_STATEWEB_THREADS);
        illegalAppPropertyValueTest(TimeMonitorAppConfig.PROPERTY_STATEWEB_THREADS, "not-an-integer");
        requireAppPropertyTest(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_LEAPSTATUSPROPERTY_NAME);
        requireAppPropertyTest(TimeMonitorAppConfig.PROPERTY_TIMESERVER_NTPDATECOMMAND);
        requireAppPropertyTest(TimeMonitorAppConfig.PROPERTY_TIMESERVER_NTPQCOMMAND);

        // Test illegal URL
        try {
            Properties props = new Properties();
            props.putAll(appProperties);
            props.setProperty(TimeMonitorAppConfig.PROPERTY_SIGNSERVER_PROCESS_URL, "not-an-URL!!");
            TimeMonitorAppConfig.load(props);
            fail("Should have failed");
        } catch (IllegalArgumentException ok) { // NOPMD
            // OK
        }

        // Test illegal bind address
        try {
            Properties props = new Properties();
            props.putAll(appProperties);
            props.setProperty(TimeMonitorAppConfig.PROPERTY_STATEWEB_BINDADDRESS, "not-an-IP-adress!!");
            TimeMonitorAppConfig.load(props);
            fail("Should have failed");
        } catch (IllegalArgumentException ok) { // NOPMD
            // OK
        }
    }

    private void requireAppPropertyTest(final String propertyName) {
        Properties props = new Properties();
        props.putAll(appProperties);
        props.remove(propertyName);
        try {
            TimeMonitorAppConfig.load(props);
            fail("Should have failed");
        } catch (IllegalArgumentException ok) { // NOPMD
            // OK
        }
    }

    private void illegalAppPropertyValueTest(final String propertyName, final String value) {
        Properties props = new Properties();
        props.putAll(appProperties);
        props.setProperty(propertyName, value);
        try {
            TimeMonitorAppConfig.load(props);
            fail("Should have failed");
        } catch (IllegalArgumentException ex) {
            // OK
        }
    }

}
