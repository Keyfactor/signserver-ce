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
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.Map;
import org.apache.log4j.Logger;
import static org.junit.Assert.*;
import org.junit.Test;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.common.data.SignatureRequest;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.server.ServicesImpl;
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

/**
 * Tests for the TimeMonitorStatusReportWroker.
 *
 * @author Markus Kilås
 * @version $Id: TimeMonitorStatusReportWorkerTest.java 5781 2015-02-25 16:29:33Z netmackan $
 */
public class TimeMonitorStatusReportWorkerTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeMonitorStatusReportWorkerTest.class);

    /**
     * Test of processData method, of class TimeMonitorStatusReportWorker.
     * s
     * @throws java.lang.Exception
     */
    @Test
    public void testProcessData() throws Exception {
        LOG.info("processData");
        final String stateLine = "1409141564440,INSYNC,REPORTED,POSITIVE";
        final StatusEntry entry = new StatusEntry(10000, stateLine, 20000);

        TimeMonitorStatusReportWorker instance = new MockTimeMonitorStatusReportWorker();
        instance.init(100, new WorkerConfig(), new SignServerContext(), null);

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData("".getBytes(StandardCharsets.UTF_8));
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            instance.processData(new SignatureRequest(1, requestData, responseData), getMockedRequestContext(entry));

            String actualStateLine = new String(responseData.toReadableData().getAsByteArray(), StandardCharsets.UTF_8);
            assertEquals(stateLine, actualStateLine);
        }
    }

    /**
     * Test of processData method, of class TimeMonitorStatusReportWorker.
     * @throws java.lang.Exception
     */
    @Test
    public void testProcessData_noInfo() throws Exception {
        LOG.info("processData_noInfo");
        final StatusEntry entry = null;

        TimeMonitorStatusReportWorker instance = new MockTimeMonitorStatusReportWorker();
        instance.init(100, new WorkerConfig(), new SignServerContext(), null);

        try (
                CloseableReadableData requestData = ModulesTestCase.createRequestData("".getBytes(StandardCharsets.UTF_8));
                CloseableWritableData responseData = ModulesTestCase.createResponseData(false);
            ) {
            instance.processData(new SignatureRequest(1, requestData, responseData), getMockedRequestContext(entry));

            String actualStateLine = new String(responseData.toReadableData().getAsByteArray(), StandardCharsets.UTF_8);
            assertEquals("n/a", actualStateLine);
        }
    }

    /** 
     * Tests that the status contains the state line.
     * @throws Exception
     */
    @Test
    public void testGetStatus() throws Exception {
        LOG.info("testGetStatus");
        final String stateLine = "1409141564445,INSYNC,REPORTED,POSITIVE";
        final StatusEntry entry = new StatusEntry(10000, stateLine, 20000);

        TimeMonitorStatusReportWorker instance = new MockTimeMonitorStatusReportWorker();
        instance.init(100, new WorkerConfig(), new SignServerContext(), null);

        ServicesImpl services = new MockedServicesImpl().with(GlobalConfigurationSessionLocal.class, new GlobalConfigurationSessionMock());
        services.put(StatusRepositorySessionLocal.class, new MockedStatusRepositorySession(entry));
        WorkerStatus status = new StaticWorkerStatus(instance.getStatus(new LinkedList<String>(), services));
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        status.displayStatus(new PrintStream(bout), true);

        String actualStatus = new String(bout.toByteArray());
        assertTrue("should contain state line but was " + actualStatus, actualStatus.contains(stateLine));
    }
    
    private RequestContext getMockedRequestContext(StatusEntry entry) {
        ServicesImpl services = new ServicesImpl();
        services.put(StatusRepositorySessionLocal.class, new MockedStatusRepositorySession(entry));
        RequestContext context = new RequestContext();
        context.setServices(services);
        return context;
    }
    
    /** Mocked worker using a status repository simply returning the configured value. */
    private static class MockTimeMonitorStatusReportWorker extends TimeMonitorStatusReportWorker {}
    
    private static class MockedStatusRepositorySession implements StatusRepositorySessionLocal {

        private final StatusEntry entry;

        public MockedStatusRepositorySession(StatusEntry entry) {
            this.entry = entry;
        }
        
        @Override
        public StatusEntry getValidEntry(String key) throws NoSuchPropertyException {
            if (StatusName.TIMEMONITOR_STATE == StatusName.valueOf(key)) {
                return entry;
            }
            return null;
        }

        @Override
        public void update(String key, String value) throws NoSuchPropertyException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public void update(String key, String value, long expiration) throws NoSuchPropertyException {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public Map<String, StatusEntry> getAllEntries() {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    };

}
