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
package org.signserver.module.timemonitormanager;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import static junit.framework.TestCase.assertEquals;
import org.apache.log4j.Logger;
import static org.junit.Assert.*;
import org.junit.Test;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerType;
import org.signserver.common.data.SignatureRequest;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.server.IServices;
import org.signserver.server.SignServerContext;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.statusrepo.StatusRepositorySessionLocal;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.StatusName;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.MockedServicesImpl;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.timemonitor.common.TimeMonitorRuntimeConfig;

/**
 * Tests for the TimeMonitorManager.
 *
 * @author Markus Kilås
 * @version $Id: TimeMonitorManagerTest.java 5781 2015-02-25 16:29:33Z netmackan $
 */
public class TimeMonitorManagerTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeMonitorManagerTest.class);

    /**
     * Tests that the init method checks any the required properties. Testing of
     * all properties are done in the TimeMonitorRuntimeConfigTest.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testInit_fail() throws Exception {
        LOG.info("testInit_fail");

        TimeMonitorManager instance = new MockTimeMonitorManager();

        WorkerConfig config = createConfig();

        // Removing one required property
        config.removeProperty(TimeMonitorRuntimeConfig.PROPERTY_MAX_ACCEPTED_OFFSET);

        instance.init(100, config, new SignServerContext(), null);
        List<String> fatalErrors = instance.getFatalErrors(new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, new GlobalConfigurationSessionMock()));
        String errors = fatalErrors.toString();
        assertEquals("[Missing required properties: [TIMEMONITOR.MAXACCEPTEDOFFSET]]", errors);
    }

    /**
     * Test setting the status properties sent by TimeMonitor.
     * @throws Exception
     */
    @Test
    public void testProcessData_setProperties() throws Exception {
        TimeMonitorManager instance = new MockTimeMonitorManager();
        WorkerConfig config = createConfig();
        instance.init(100, config, new SignServerContext(), null);
        IServices services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, new GlobalConfigurationSessionMock());
        List<String> fatalErrors = instance.getFatalErrors(services);
        if (!fatalErrors.isEmpty()) {
            throw new Exception("Error in test case: " + fatalErrors);
        }

        Date now = new Date();

        String expiration1 = String.valueOf(now.getTime() + 3000001L);
        String expiration2 = String.valueOf(now.getTime() + 3000002L);
        String expiration3 = String.valueOf(now.getTime() + 3000003L);
        String expiration4 = String.valueOf(now.getTime() + 3000004L);

        final String value1 = "value 1";
        final String value2 = "value 2";
        final String value3 = "value 3";
        final String value4 = "value 4";

        Properties requestProps = new Properties();
        requestProps.setProperty(StatusName.TIMESOURCE0_INSYNC.name() + ".VALUE", value1);
        requestProps.setProperty(StatusName.LEAPSECOND.name() + ".VALUE", value2);
        requestProps.setProperty(StatusName.TIMEMONITOR_STATE.name() + ".VALUE", value3);
        requestProps.setProperty(StatusName.TIMEMONITOR_LOG.name() + ".VALUE", value4);
        requestProps.setProperty(StatusName.TIMESOURCE0_INSYNC.name() + ".EXPIRATION", expiration1);
        requestProps.setProperty(StatusName.LEAPSECOND.name() + ".EXPIRATION", expiration2);
        requestProps.setProperty(StatusName.TIMEMONITOR_STATE.name() + ".EXPIRATION", expiration3);
        requestProps.setProperty(StatusName.TIMEMONITOR_LOG.name() + ".EXPIRATION", expiration4);

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(requestProps);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            instance.processData(new SignatureRequest(123, requestData, responseData), new RequestContext());
            Properties responseProps;
            try (InputStream in = responseData.toReadableData().getAsInputStream()) {
                responseProps = new Properties();
                responseProps.load(in);
            }

            // Should have set update time for the properties
            assertNotNull(responseProps.getProperty(StatusName.TIMESOURCE0_INSYNC.name() + ".UPDATE"));
            assertNotNull(responseProps.getProperty(StatusName.LEAPSECOND.name() + ".UPDATE"));
            assertNotNull(responseProps.getProperty(StatusName.TIMEMONITOR_STATE.name() + ".UPDATE"));
            assertNotNull(responseProps.getProperty(StatusName.TIMEMONITOR_LOG.name() + ".UPDATE"));

            // Check the values in the repository
            Map<String, StatusEntry> allEntries = instance.getStatusRepository(services).getAllEntries();
            StatusEntry entry1 = allEntries.get(StatusName.TIMESOURCE0_INSYNC.name());
            StatusEntry entry2 = allEntries.get(StatusName.LEAPSECOND.name());
            StatusEntry entry3 = allEntries.get(StatusName.TIMEMONITOR_STATE.name());
            StatusEntry entry4 = allEntries.get(StatusName.TIMEMONITOR_LOG.name());
            assertEquals(value1, entry1.getValue());
            assertEquals(value2, entry2.getValue());
            assertEquals(value3, entry3.getValue());
            assertEquals(value4, entry4.getValue());

            // Should not send any config as we did not request it
            for (String key : responseProps.stringPropertyNames()) {
                if (key.startsWith("TIMEMONITOR.") || key.startsWith("TIMESERVER.")) {
                    fail("Unexpected property sent: " + key);
                }
            }
            assertNull("config version", responseProps.getProperty("CONFIG"));
        }
    }

    /**
     * Tests that no config is sent if it is already the newest version.
     * @throws java.lang.Exception
     */
    @Test
    public void testProcessData_requestSameConfig() throws Exception {
        TimeMonitorManager instance = new MockTimeMonitorManager();
        String currentVersion = Integer.toHexString(instance.hashCode());
        WorkerConfig config = createConfig();
        instance.init(100, config, new SignServerContext(), null);
        List<String> fatalErrors = instance.getFatalErrors(new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, new GlobalConfigurationSessionMock()));
        if (!fatalErrors.isEmpty()) {
            throw new Exception("Error in test case: " + fatalErrors);
        }

        Properties requestProps = new Properties();
        // We don't bother putting in any properties in this test except
        // for CONFIG
        requestProps.setProperty("CONFIG", currentVersion);

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(requestProps);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            instance.processData(new SignatureRequest(123, requestData, responseData), new RequestContext());
            Properties responseProps;
            try (InputStream in = responseData.toReadableData().getAsInputStream()) {
                responseProps = new Properties();
                responseProps.load(in);
            }

            // Should not send any config as we already have latest version
            for (String key : responseProps.stringPropertyNames()) {
                if (key.startsWith("TIMEMONITOR.") || key.startsWith("TIMESERVER.")) {
                    fail("Unexpected property sent: " + key);
                }
            }
            assertNull("config version", responseProps.getProperty("CONFIG"));
        }
    }

    /**
     * Tests that we get a config when a new is available
     * @throws java.lang.Exception
     */
    @Test
    public void testProcessData_requestNewConfig() throws Exception {
        TimeMonitorManager instance = new MockTimeMonitorManager();
        String ourVersion = "1111";
        WorkerConfig config = createConfig();
        instance.init(100, config, new SignServerContext(), null);
        List<String> fatalErrors = instance.getFatalErrors(new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, new GlobalConfigurationSessionMock()));
        if (!fatalErrors.isEmpty()) {
            throw new Exception("Error in test case: " + fatalErrors);
        }

        Properties requestProps = new Properties();
        // We don't bother putting in any properties in this test except
        // for CONFIG
        requestProps.setProperty("CONFIG", ourVersion);

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData(requestProps);
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            instance.processData(new SignatureRequest(123, requestData, responseData), new RequestContext());
            Properties responseProps;
            try (InputStream in = responseData.toReadableData().getAsInputStream()) {
                responseProps = new Properties();
                responseProps.load(in);
            }

            // Should get a new config
            assertNotNull("config version", responseProps.getProperty("CONFIG"));
            for (String property : config.getProperties().stringPropertyNames()) {
                if (property.startsWith("TIMESERVER.") || property.startsWith("TIMEMONITOR.")) {
                    assertEquals("property " + property, config.getProperty(property), responseProps.getProperty(property));
                }
            }
        }
    }

    /**
     * Tests that the status print code can be executed when there is no
     * status properties available.
     * @throws Exception
     */
    @Test
    public void testGetStatus_Unavailable() throws Exception {
        LOG.info("testGetStatus_Unavailable");
        TimeMonitorManager instance = new MockTimeMonitorManager();
        WorkerConfig config = createConfig();
        instance.init(100, config, new SignServerContext(), null);
        IServices services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, new GlobalConfigurationSessionMock());
        List<String> fatalErrors = instance.getFatalErrors(services);
        if (!fatalErrors.isEmpty()) {
            throw new Exception("Error in test case: " + fatalErrors);
        }

        WorkerStatus status = new StaticWorkerStatus(instance.getStatus(new LinkedList<String>(), services));
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        status.displayStatus(new PrintStream(bout), true);

        String actualStatus = new String(bout.toByteArray());
        LOG.info(actualStatus);
        assertTrue("should contain unavailable " + actualStatus, actualStatus.contains("Unavailable"));
    }

     /**
     * Tests that the status print code can be executed when there is
     * information available.
     * @throws Exception
     */
    @Test
    public void testGetStatus() throws Exception {
        LOG.info("testGetStatus");

        final EnumMap<StatusName, StatusEntry> statusProps = new EnumMap<>(StatusName.class);
        long expireTime = System.currentTimeMillis() + 3000000;
        statusProps.put(StatusName.TIMESOURCE0_INSYNC, new StatusEntry(1000, "true", expireTime));
        statusProps.put(StatusName.LEAPSECOND, new StatusEntry(1000, "NONE", expireTime));
        statusProps.put(StatusName.TIMEMONITOR_STATE, new StatusEntry(1000, "1409141564440,INSYNC,REPORTED,NONE,b526098,13,507,8,7", expireTime));
        statusProps.put(StatusName.TIMEMONITOR_LOG, new StatusEntry(1000, "Log row 1\nLog row 2\nLog row 3", expireTime));

        TimeMonitorManager instance = new MockTimeMonitorManager(statusProps);
        WorkerConfig config = createConfig();
        instance.init(100, config, new SignServerContext(), null);
        IServices services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, new GlobalConfigurationSessionMock());
        List<String> fatalErrors = instance.getFatalErrors(services);
        if (!fatalErrors.isEmpty()) {
            throw new Exception("Error in test case: " + fatalErrors);
        }

        WorkerStatus status = new StaticWorkerStatus(instance.getStatus(new LinkedList<String>(), services));
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        status.displayStatus(new PrintStream(bout), true);

        String actualStatus = new String(bout.toByteArray());
        LOG.info(actualStatus);

        // Test that some of the values are printed
        assertTrue("should contain INSYNC ", actualStatus.contains("INSYNC"));
        assertTrue("should contain NONE ", actualStatus.contains("NONE"));
        assertTrue("should contain NTP server time offset", actualStatus.contains("NTP server time offset"));
        assertTrue("should contain Log row 1", actualStatus.contains("Log row 1"));
        assertTrue("should contain Log row 2", actualStatus.contains("Log row 2"));
        assertTrue("should contain Log row 3", actualStatus.contains("Log row 3"));
    }

    private static WorkerConfig createConfig() {
        WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        config.setProperty(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_HOST, "192.168.0.1");
        config.setProperty(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_SENDSAMPLES, "3");
        config.setProperty(TimeMonitorRuntimeConfig.PROPERTY_TIMESERVER_TIMEOUT, "0.4");
        config.setProperty(TimeMonitorRuntimeConfig.PROPERTY_MAX_ACCEPTED_OFFSET, "900");
        config.setProperty(TimeMonitorRuntimeConfig.PROPERTY_WARN_OFFSET, "500");
        config.setProperty(TimeMonitorRuntimeConfig.PROPERTY_STATUS_EXPIRE_TIME, "2000");
        config.setProperty(TimeMonitorRuntimeConfig.PROPERTY_LEAPSTATUS_EXPIRE_TIME, "70000");
        config.setProperty(TimeMonitorRuntimeConfig.PROPERTY_MIN_RUN_TIME, "500");
        config.setProperty(TimeMonitorRuntimeConfig.PROPERTY_WARN_RUN_TIME, "1000");
        config.setProperty(TimeMonitorRuntimeConfig.PROPERTY_DISABLED, "false");
        config.setProperty("AnyUnrelatedProperty", "SomeValue");
        return config;
    }


    /** Mocked worker using a status repository simply returning the configured value. */
    private static class MockTimeMonitorManager extends TimeMonitorManager {

        private final StatusRepositorySessionLocal repo;

        public MockTimeMonitorManager() {
            this(new EnumMap<StatusName, StatusEntry>(StatusName.class));
        }

        public MockTimeMonitorManager(final Map<StatusName, StatusEntry> datas) {
            this.repo = new StatusRepositorySessionLocal() {

                @Override
                public StatusEntry getValidEntry(String key) throws NoSuchPropertyException {
                    StatusEntry result = datas.get(StatusName.valueOf(key));
                    if (result == null) {
                        throw new NoSuchPropertyException(key);
                    }
                    // We don't care about validity yet so just return the entry
                    return result;
                }

                @Override
                public void update(String key, String value) throws NoSuchPropertyException {
                    datas.put(StatusName.valueOf(key), new StatusEntry(System.currentTimeMillis(), value, 0));
                }

                @Override
                public void update(String key, String value, long expiration) throws NoSuchPropertyException {
                    datas.put(StatusName.valueOf(key), new StatusEntry(System.currentTimeMillis(), value, expiration));
                }

                @Override
                public Map<String, StatusEntry> getAllEntries() {
                    Map<String, StatusEntry> result = new HashMap<>();
                    for (Entry<StatusName, StatusEntry> entry : datas.entrySet()) {
                        result.put(entry.getKey().name(), entry.getValue());
                    }
                    return result;
                }
            };
        }

        @Override
        protected StatusRepositorySessionLocal getStatusRepository(IServices services) {
            return repo;
        }

    }

}
