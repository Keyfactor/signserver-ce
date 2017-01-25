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
package org.signserver.module.renewal.service;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.common.WorkerType;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.test.utils.mock.MockedServicesImpl;
import org.signserver.test.utils.mock.WorkerSessionMock;
import static junit.framework.TestCase.assertTrue;

/**
 * Unit tests for the the RenewalTimedService.
 *
 * See also the project SignServer-Test-Renewal for system tests.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class RenewalTimedServiceUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(RenewalTimedServiceUnitTest.class);


    /**
     * Tests the checking of required worker properties.
     */
    @Test
    public void testInit() {
        LOG.info("testInit");
        
        int workerId = 0;
        WorkerContext workerContext = null;
        EntityManager workerEM = null;
        RenewalTimedService instance = new RenewalTimedService();
        
        // Without any properties
        WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.TIMED_SERVICE.name());
        instance.init(workerId, config, workerContext, workerEM);
        List<String> fatalErrors = instance.getFatalErrors(null);
        assertTrue("Should contain error but was: " + fatalErrors, fatalErrors.contains("Missing required property: WORKERS"));

        // With all required propertues
        config.setProperty("WORKERS", "Worker1");
        instance = new RenewalTimedService();
        instance.init(workerId, config, workerContext, workerEM);
        fatalErrors = instance.getFatalErrors(null);
        assertEquals("Should not contain errors but was: " + fatalErrors, 0, fatalErrors.size());
    }

    /**
     * Tests that the status information contains information about the renewal
     * state.
     * @throws java.lang.Exception
     */
    @Test
    public void testGetStatus() throws Exception {
        LOG.info("testGetStatus");
        List<String> additionalFatalErrors = Collections.emptyList();
        
        // Setup some workers
        WorkerConfig config201 = new WorkerConfig();
        config201.setProperty("RENEWWORKER", "RenewalWorker1");
        Date date201 = new Date();
        
        WorkerConfig config202 = new WorkerConfig();
        config202.setProperty("RENEWWORKER", "RenewalWorker2");
        Date date202 = new Date();
        
        WorkerConfig config203 = new WorkerConfig();
        config203.setProperty("RENEWWORKER", "RenewalWorker3");
        Date date203 = new Date();
        
        // Mocked services
        IServices services = new MockedServicesImpl().with(WorkerSessionLocal.class, new MyMockedWorkerSession(Arrays.asList(
                new MockedWorker(201, "Worker1", config201, date201),
                new MockedWorker(202, "Worker2", config202, date202),
                new MockedWorker(203, "Worker3", config203, date203)
        )));
        
        // Init the service
        int workerId = 103;
        WorkerContext workerContext = null;
        EntityManager workerEM = null;
        WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.TIMED_SERVICE.name());
        config.setProperty("WORKERS", " Worker1 , Worker2,Worker3");
        RenewalTimedService instance = new RenewalTimedService();
        instance.init(workerId, config, workerContext, workerEM);
        List<String> fatalErrors = instance.getFatalErrors(null);
        if (!fatalErrors.isEmpty()) {
            throw new Exception("Config errors: " + fatalErrors);
        }
        
        // Get the workers renewal prognose
        WorkerStatusInfo result = instance.getStatus(additionalFatalErrors, services);
        Map<String, String> entries = getEntriesMap(result.getCompleteEntries());
        String renewalInfo = entries.get("Workers Renewal Prognose");
        assertNotNull("Expected a \"Workers Renewal Prognose\" but only found: " + entries.keySet(), renewalInfo);
        
        // Should contain information for each configured worker
        System.out.println(renewalInfo);
        assertTrue("Should contain Worker1: " + renewalInfo, renewalInfo.contains("Worker1"));
        assertTrue("Should contain Worker2: " + renewalInfo, renewalInfo.contains("Worker2"));
        assertTrue("Should contain Worker3: " + renewalInfo, renewalInfo.contains("Worker3"));
        assertTrue("Should contain Worker1 ID: " + renewalInfo, renewalInfo.contains("201"));
        assertTrue("Should contain Worker2 ID: " + renewalInfo, renewalInfo.contains("202"));
        assertTrue("Should contain Worker3 ID: " + renewalInfo, renewalInfo.contains("203"));
    }
    
    private static Map<String, String> getEntriesMap(Collection<WorkerStatusInfo.Entry> entries) {
        final HashMap<String, String> results = new HashMap<>(entries.size());
        for (WorkerStatusInfo.Entry entry : entries) {
            results.put(entry.getTitle(), entry.getValue());
        }
        return results;
    }

    /**
     * Tests getRenewalStatuses with workers that are configured with a renewWorker.
     * @throws java.lang.Exception
     */
    @Test
    public void testGetRenewalStatuses_ok() throws Exception {
        LOG.info("testGetRenewalStatuses");

        WorkerConfig config201 = new WorkerConfig();
        config201.setProperty("RENEWWORKER", "RenewalWorker1");
        WorkerConfig config202 = new WorkerConfig();
        config202.setProperty("RENEWWORKER", "RenewalWorker2");
        WorkerConfig config203 = new WorkerConfig();
        config203.setProperty("RENEWWORKER", "RenewalWorker3");

        // Get the renewal statuses
        List<RenewalTimedService.RenewalStatus> result = getRenewalStatusesHelper(new Date(), config201, new Date(), config202, new Date(), config203, new Date());
        
        assertEquals("num statuses", 3, result.size());
        
        // We expect results from each worker
        RenewalTimedService.RenewalStatus status201 = getById(result, 201);
        RenewalTimedService.RenewalStatus status202 = getById(result, 202);
        RenewalTimedService.RenewalStatus status203 = getById(result, 203);
        assertNotNull("status for 201", status201);
        assertNotNull("status for 202", status202);
        assertNotNull("status for 203", status203);
        assertEquals("worker name", "Worker1", status201.getWorkerName());
        assertEquals("worker name", "Worker2", status202.getWorkerName());
        assertEquals("worker name", "Worker3", status203.getWorkerName());
        
        // Each with their own renewal worker
        assertEquals("renewal worker", "RenewalWorker1", status201.getRenewalWorker());
        assertEquals("renewal worker", "RenewalWorker2", status202.getRenewalWorker());
        assertEquals("renewal worker", "RenewalWorker3", status203.getRenewalWorker());
        
        // No errors
        assertNull("no error: " + status201.getError(), status201.getError());
        assertNull("no error: " + status202.getError(), status202.getError());
        assertNull("no error: " + status203.getError(), status203.getError());
        assertNotNull("date for 201", status201.getRenewalDate());
        assertNotNull("date for 202", status202.getRenewalDate());
        assertNotNull("date for 203", status203.getRenewalDate());
        
        // Default value for FORDEFAULTKEY
        assertFalse("forDefaultKey default", status201.isForDefaultKey());
        assertFalse("forDefaultKey default", status202.isForDefaultKey());
        assertFalse("forDefaultKey default", status203.isForDefaultKey());
    }
    
    /**
     * Tests getRenewalStatuses with workers that one is missing the 
     * RenewalWorker.
     * @throws java.lang.Exception
     */
    @Test
    public void testGetRenewalStatuses_missingRenewalWorker() throws Exception {
        LOG.info("testGetRenewalStatuses_missingRenewalWorker");

        WorkerConfig config201 = new WorkerConfig();
        config201.setProperty("RENEWWORKER", "RenewalWorker1");
        WorkerConfig config202 = new WorkerConfig(); // Note: Without RENEWWORKER property        
        WorkerConfig config203 = new WorkerConfig();
        config203.setProperty("RENEWWORKER", "RenewalWorker3");

        // Get the renewal statuses
        List<RenewalTimedService.RenewalStatus> result = getRenewalStatusesHelper(new Date(), config201, new Date(), config202, new Date(), config203, new Date());
        
        assertEquals("num statuses", 3, result.size());
        
        // We expect results from each worker
        RenewalTimedService.RenewalStatus status201 = getById(result, 201);
        RenewalTimedService.RenewalStatus status202 = getById(result, 202);
        RenewalTimedService.RenewalStatus status203 = getById(result, 203);
        assertNotNull("status for 201", status201);
        assertNotNull("status for 202", status202);
        assertNotNull("status for 203", status203);
        assertEquals("worker name", "Worker1", status201.getWorkerName());
        assertEquals("worker name", "Worker2", status202.getWorkerName());
        assertEquals("worker name", "Worker3", status203.getWorkerName());
        
        // Each with their own renewal worker
        assertEquals("renewal worker", "RenewalWorker1", status201.getRenewalWorker());
        assertNull("no renewal worker", status202.getRenewalWorker());
        assertEquals("renewal worker", "RenewalWorker3", status203.getRenewalWorker());
        
        // Only error for worker 202
        assertNull("no error: " + status201.getError(), status201.getError());
        assertNotNull("error about missing RENEWWORKER property", status202.getError());
        assertTrue("should contain error about missing RENEWWORKER property: " + status202.getError(), status202.getError().contains("RENEWWORKER"));
        assertNull("no error: " + status203.getError(), status203.getError());
        assertNotNull("date for 201", status201.getRenewalDate());
        assertNotNull("date for 203", status203.getRenewalDate());
    }
    
    /**
     * Tests getRenewalStatuses with workers that have configured
     * RENEW_FORDEFAULTKEY.
     * @throws java.lang.Exception
     */
    @Test
    public void testGetRenewalStatuses_renewForDefaultKey() throws Exception {
        LOG.info("testGetRenewalStatuses_renewForDefaultKey");

        WorkerConfig config201 = new WorkerConfig();
        config201.setProperty("RENEWWORKER", "RenewalWorker1");
        config201.setProperty("RENEW_FORDEFAULTKEY", "true"); // Note: forDefaultKey=true
        WorkerConfig config202 = new WorkerConfig();
        config202.setProperty("RENEWWORKER", "RenewalWorker2");
        config202.setProperty("RENEW_FORDEFAULTKEY", "false"); // Note: forDefaultKey=false
        WorkerConfig config203 = new WorkerConfig(); // Note: No forDefaultKey, default should be false
        config203.setProperty("RENEWWORKER", "RenewalWorker3");
        

        // Get the renewal statuses
        List<RenewalTimedService.RenewalStatus> result = getRenewalStatusesHelper(new Date(), config201, new Date(), config202, new Date(), config203, new Date());        
        assertEquals("num statuses", 3, result.size());
        
        // We expect results from each worker
        RenewalTimedService.RenewalStatus status201 = getById(result, 201);
        RenewalTimedService.RenewalStatus status202 = getById(result, 202);
        RenewalTimedService.RenewalStatus status203 = getById(result, 203);

        // Check forDefaultKey
        assertTrue(status201.isForDefaultKey());
        assertFalse(status202.isForDefaultKey());
        assertFalse(status203.isForDefaultKey());
    }
    
    /**
     * Tests the worker property RENEW_MINREMAININGSIGNINGVALIDITY with one
     * incorrect value.
     * @throws java.lang.Exception
     */
    @Test
    public void testGetRenewalStatuses_renewMinRemainingSigningValidity_incorrect() throws Exception {
        LOG.info("testGetRenewalStatuses_renewMinRemainingSigningValidity_incorrect");

        WorkerConfig config201 = new WorkerConfig();
        config201.setProperty("RENEWWORKER", "RenewalWorker1");
        config201.setProperty("RENEW_MINREMAININGSIGNINGVALIDITY", "2d"); // Note: 2 days
        WorkerConfig config202 = new WorkerConfig();
        config202.setProperty("RENEWWORKER", "RenewalWorker2");
        config202.setProperty("RENEW_MINREMAININGSIGNINGVALIDITY", "_Incorrect_Value"); // Note: incorrect value
        WorkerConfig config203 = new WorkerConfig(); // Note: No RENEW_MINREMAININGSIGNINGVALIDITY, default is 0d
        config203.setProperty("RENEWWORKER", "RenewalWorker3");

        // Now: 2016-03-04 14:00:00,000
        Calendar cal = Calendar.getInstance();
        cal.clear();
        cal.set(2016, 3, 4, 14, 0, 0);
        final Date now = cal.getTime();

        // Less than 2 days
        cal.clear();
        cal.set(2016, 3, 6, 13, 59, 59);
        final Date lessThan2d = cal.getTime();

        // Get the renewal statuses
        List<RenewalTimedService.RenewalStatus> result = getRenewalStatusesHelper(now, config201, lessThan2d, config202, lessThan2d, config203, lessThan2d);
        RenewalTimedService.RenewalStatus status201 = getById(result, 201);
        RenewalTimedService.RenewalStatus status202 = getById(result, 202);
        RenewalTimedService.RenewalStatus status203 = getById(result, 203);

        // Worker 202 is the only one that should be up for renewal
        assertTrue("up for renewal", status201.isRenew());
        assertNotNull("expected error for 202", status202.getError());
        assertTrue("expected error about RENEW_MINREMAININGSIGNINGVALIDITY: " + status202.getError(), status202.getError().contains("RENEW_MINREMAININGSIGNINGVALIDITY"));
        assertFalse("not up for renewal but is: " + status203.getRenewalDate(), status203.isRenew());
    }
    
    /**
     * Tests different values for RENEW_MINREMAININGSIGNINGVALIDITY, different
     * values for signing validity and then varying time.
     * @throws java.lang.Exception
     */
    @Test
    public void testGetRenewalStatuses_renewMinRemainingSigningValidity() throws Exception {
        LOG.info("testGetRenewalStatuses_renewMinRemainingSigningValidity");

        WorkerConfig config201 = new WorkerConfig();
        config201.setProperty("RENEWWORKER", "RenewalWorker1");
        config201.setProperty("RENEW_MINREMAININGSIGNINGVALIDITY", "4d"); // Note: 4 days
        WorkerConfig config202 = new WorkerConfig();
        config202.setProperty("RENEWWORKER", "RenewalWorker2");
        config202.setProperty("RENEW_MINREMAININGSIGNINGVALIDITY", "4d 2h 3s"); // Note: 4 days, 2 hours and 3 seconds
        WorkerConfig config203 = new WorkerConfig(); // Note: No RENEW_MINREMAININGSIGNINGVALIDITY, default is 0d
        config203.setProperty("RENEWWORKER", "RenewalWorker3");
        config203.setProperty("RENEW_MINREMAININGSIGNINGVALIDITY", "10810s"); // Note: 3 hours and 10 seconds

        Calendar cal = Calendar.getInstance();

        // Expire201: 2016-04-05 10:00:00,000
        cal.clear();
        cal.set(2016, 4, 5, 10, 00, 00);
        final Date expire201 = cal.getTime();
        System.out.println("expire201: " + expire201);
        
        // Expire202: 2016-04-05 12:00:00,000
        cal.clear();
        cal.set(2016, 4, 5, 10, 00, 00);
        final Date expire202 = cal.getTime();
        
        // Expire203: 2016-04-01 13:00:00,000
        cal.clear();
        cal.set(2016, 4, 1, 13, 00, 10);
        final Date expire203 = cal.getTime();

        // Now: 2016-02-01 05:00:00,000: An early date so no renewal
        cal.clear();
        cal.set(2016, 4, 1, 5, 00, 00);
        Date now = cal.getTime();
        List<RenewalTimedService.RenewalStatus> result = getRenewalStatusesHelper(now, config201, expire201, config202, expire202, config203, expire203);
        assertFalse("up for renewal: " + getById(result, 201).getRenewalDate(), getById(result, 201).isRenew());
        assertFalse("up for renewal: " + getById(result, 202).getRenewalDate(), getById(result, 202).isRenew());
        assertFalse("up for renewal: " + getById(result, 203).getRenewalDate(), getById(result, 203).isRenew());
        
        // Now: 2016-03-01 07:59:57,000: Now = 4d 2h 3s to expire for 202
        cal.clear();
        cal.set(2016, 4, 1, 7, 59, 57);
        now = cal.getTime();
        result = getRenewalStatusesHelper(now, config201, expire201, config202, expire202, config203, expire203);
        assertFalse("up for renewal: " + getById(result, 201).getRenewalDate(), getById(result, 201).isRenew());
        assertFalse("up for renewal: " + getById(result, 202).getRenewalDate(), getById(result, 202).isRenew());
        assertFalse("up for renewal: " + getById(result, 203).getRenewalDate(), getById(result, 203).isRenew());
        
        // Now: 2016-03-01 07:59:58,000: Now less tan 4d 2h 3s to expire for 202
        cal.clear();
        cal.set(2016, 4, 1, 7, 59, 58);
        now = cal.getTime();
        result = getRenewalStatusesHelper(now, config201, expire201, config202, expire202, config203, expire203);
        assertFalse("up for renewal: " + getById(result, 201).getRenewalDate(), getById(result, 201).isRenew());
        assertTrue("up for renewal: " + getById(result, 202).getRenewalDate(), getById(result, 202).isRenew());
        assertFalse("up for renewal: " + getById(result, 203).getRenewalDate(), getById(result, 203).isRenew());
        
        // Now: 2016-03-01 10:00:00,000: Now = 4d to expire for 201
        cal.clear();
        cal.set(2016, 4, 1, 10, 0, 0);
        now = cal.getTime();
        result = getRenewalStatusesHelper(now, config201, expire201, config202, expire202, config203, expire203);
        assertFalse("up for renewal: " + getById(result, 201).getRenewalDate(), getById(result, 201).isRenew());
        assertTrue("up for renewal: " + getById(result, 202).getRenewalDate(), getById(result, 202).isRenew());
        assertFalse("up for renewal: " + getById(result, 203).getRenewalDate(), getById(result, 203).isRenew());
        
        // Now: 2016-03-01 10:00:01,000: Now less than 4d to expire for 201 
        cal.clear();
        cal.set(2016, 4, 1, 10, 0, 1);
        now = cal.getTime();
        result = getRenewalStatusesHelper(now, config201, expire201, config202, expire202, config203, expire203);
        assertTrue("up for renewal: " + getById(result, 201).getRenewalDate(), getById(result, 201).isRenew());
        assertTrue("up for renewal: " + getById(result, 202).getRenewalDate(), getById(result, 202).isRenew());
        assertTrue("up for renewal: " + getById(result, 203).getRenewalDate(), getById(result, 203).isRenew());
    }
    
    private List<RenewalTimedService.RenewalStatus> getRenewalStatusesHelper(Date now, WorkerConfig config201, Date date201, WorkerConfig config202, Date date202, WorkerConfig config203, Date date203) throws Exception {
        final List<String> workers = Arrays.asList("Worker1", "Worker2", "Worker3");

        // Init the service
        int workerId = 104;
        WorkerContext workerContext = null;
        EntityManager workerEM = null;
        WorkerConfig config = new WorkerConfig();
        config.setProperty(WorkerConfig.TYPE, WorkerType.TIMED_SERVICE.name());
        config.setProperty("WORKERS", " Worker1 , Worker2,Worker3");
        RenewalTimedService instance = new RenewalTimedService();
        instance.init(workerId, config, workerContext, workerEM);
        List<String> fatalErrors = instance.getFatalErrors(null);
        if (!fatalErrors.isEmpty()) {
            throw new Exception("Config errors: " + fatalErrors);
        }
        
        // Get the renewal statuses
        List<RenewalTimedService.RenewalStatus> result = instance.getRenewalStatuses(workers, now, new MyMockedWorkerSession(Arrays.asList(
                new MockedWorker(201, "Worker1", config201, date201),
                new MockedWorker(202, "Worker2", config202, date202),
                new MockedWorker(203, "Worker3", config203, date203)
        )));

        assertEquals("num statuses", 3, result.size());

        return result;
    }
    
    private static RenewalTimedService.RenewalStatus getById(List<RenewalTimedService.RenewalStatus> statuses, int id) {
        RenewalTimedService.RenewalStatus result = null;
        for (RenewalTimedService.RenewalStatus status : statuses) {
            if (status.getWorkerId() == id) {
                result = status;
                break;
            }
        }
        return result;
    }
    
    
    private static class MockedWorker {
        private final int id;
        private final String name;
        private final WorkerConfig config;
        private final Date signingValidity;

        public MockedWorker(int id, String name, WorkerConfig config, Date signingValidity) {
            this.id = id;
            this.name = name;
            this.config = config;
            this.signingValidity = signingValidity;
        }

    }

    private static class MyMockedWorkerSession extends WorkerSessionMock {

        private final HashMap<Integer, MockedWorker> workersById = new HashMap<>();
        private final HashMap<String, MockedWorker> workersByName = new HashMap<>();

        public MyMockedWorkerSession(Collection<MockedWorker> workers) {
            for (MockedWorker worker : workers) {
                workersById.put(worker.id, worker);
                workersByName.put(worker.name, worker);
            }   
        }

        @Override
        public int getWorkerId(String workerName) throws InvalidWorkerIdException {
            final int result;
            final MockedWorker worker = workersByName.get(workerName);
            if (worker == null) {
                throw new InvalidWorkerIdException("No such worker: " + workerName);
            } else {
                result = worker.id;
            }
            return result;
        }

        @Override
        public WorkerConfig getCurrentWorkerConfig(int signerId) {
            final WorkerConfig result;
            final MockedWorker worker = workersById.get(signerId);
            if (worker == null) {
                LOG.error("No such worker ID: " + signerId);
                result = null;
            } else {
                result = worker.config;
            }
            return result;
        }

        @Override
        public Date getSigningValidityNotAfter(WorkerIdentifier workerId) throws CryptoTokenOfflineException {
            final Date result;
            final MockedWorker worker;
            if (workerId.hasId()) {
                worker = workersById.get(workerId.getId());
            } else {
                worker = workersByName.get(workerId.getName());
            }
            if (worker == null) {
                LOG.error("No such worker: " + workerId);
                result = null;
            } else {
                result = worker.signingValidity;
            }
            return result;
        }
    }
    
}
