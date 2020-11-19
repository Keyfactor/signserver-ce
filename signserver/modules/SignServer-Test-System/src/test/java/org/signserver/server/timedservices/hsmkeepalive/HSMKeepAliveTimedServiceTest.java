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
package org.signserver.server.timedservices.hsmkeepalive;

import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.ServiceConfig;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerIdentifier;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.StatusName;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.statusrepo.StatusRepositorySession;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * System test for the HSM keep-alive timed service.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class HSMKeepAliveTimedServiceTest extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(HSMKeepAliveTimedServiceTest.class);

    private static final int WORKERID_SERVICE = 5800;
    private static final int WORKERID_CRYPTOWORKER1 = 5801;
    private static final int WORKERID_CRYPTOWORKER2 = 5802;

    private final WorkerSession workerSession = getWorkerSession();
    private final StatusRepositorySession statusSession = getStatusSession();

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    private void waitForServiceToRun(final Collection<Integer> workerIds) {

         try {
            for (int i = 0; i < 30; i++) {
                boolean missingAlias = false;

                Thread.sleep(1000);

                for (final int workerId : workerIds) {
                    if (getDebugKeyAlias(workerId) == null) {
                        missingAlias = true;
                        break;
                    }
                }

                if (!missingAlias) {
                    break;
                }
            }
        } catch (InterruptedException ex) {
            LOG.error("Interrupted", ex);
        }
    }

    private String getDebugKeyAlias(final int workerId) {
        try {
            StatusEntry entry;
            switch (workerId) {
                case WORKERID_CRYPTOWORKER1:
                    entry = statusSession.getValidEntry(StatusName.TEST_PROPERTY1.name());
                    break;
                case WORKERID_CRYPTOWORKER2:
                    entry = statusSession.getValidEntry(StatusName.TEST_PROPERTY2.name());
                    break;
                default:
                    LOG.error("Unknown crypto worker ID: " + workerId);
                    return null;
            }

            if (entry != null) {
                return entry.getValue();
            } else {
                return null;
            }

        } catch (NoSuchPropertyException e) {
            LOG.error("Unknown status property: " + e.getMessage());
            return null;
        }
    }

    private void setServiceActive(final boolean active) {
        workerSession.setWorkerProperty(WORKERID_SERVICE, ServiceConfig.ACTIVE,
                Boolean.valueOf(active).toString());
        workerSession.reloadConfiguration(WORKERID_SERVICE);

        if (!active) {
            // when shutting down the service, add some delay to give it time
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ex) {
                //NoPMD: ignored
            }
        }
    }

    private void resetStatus() {
        // stop service (will sleep a bit to avoid race)
        setServiceActive(false);
        // reset status repository
        try {
            statusSession.update(StatusName.TEST_PROPERTY1.name(), null);
            statusSession.update(StatusName.TEST_PROPERTY2.name(), null);
        } catch (NoSuchPropertyException e) {
            LOG.error("Unknown status property: " + e.getMessage());
        }
    }

    @Test
    public void test00setupDatabase() throws Exception {
        setProperties(new File(getSignServerHome(), "res/test/test-hsmkeepalive-configuration.properties"));

        workerSession.reloadConfiguration(WORKERID_SERVICE);
        workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
        workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER2);
    }

    /**
     * Test a basic configuration with two crypto workers set up with the
     * TESTKEY key alias property.
     */
    @Test
    public void test01runServiceWithTwoWorkers() {
        try {
            setServiceActive(true);
            // make sure the service had time to run
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER1, WORKERID_CRYPTOWORKER2)
            );

            final String keyAlias1 = getDebugKeyAlias(WORKERID_CRYPTOWORKER1);
            final String keyAlias2 = getDebugKeyAlias(WORKERID_CRYPTOWORKER2);

            // check that the service has run and tested keys for both configured workers
            assertNotNull("testKey run on worker 1", keyAlias1);
            assertNotNull("testKey run on worker 2", keyAlias2);
            assertEquals("TESTKEY alias used for worker 1",
                         "TestKey1", keyAlias1);
            assertEquals("TESTKEY alias used for worker 2",
                         "TestKey2", keyAlias2);
        } finally {
            resetStatus();
        }
    }

    /**
     * Test that when setting DEFAULTKEY, TESTKEY is still used.
     */
    @Test
    public void test02runServiceWithTestAndDefaultKey() {
        try {
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER1,
                    "DEFAULTKEY", "DefaultKey1");
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER2,
                    "DEFAULTKEY", "DefaultKey2");
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER2);

            setServiceActive(true);
            // make sure the service had time to run
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER1, WORKERID_CRYPTOWORKER2)
            );

            final String keyAlias1 = getDebugKeyAlias(WORKERID_CRYPTOWORKER1);
            final String keyAlias2 = getDebugKeyAlias(WORKERID_CRYPTOWORKER2);

            // check that the service has run and tested keys for both configured workers
            assertNotNull("testKey run on worker 1", keyAlias1);
            assertNotNull("testKey run on worker 2", keyAlias2);
            assertEquals("TESTKEY alias used for worker 1",
                         "TestKey1", keyAlias1);
            assertEquals("TESTKEY alias used for worker 2",
                         "TestKey2", keyAlias2);
        } finally {
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER1, "DEFAULTKEY");
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER2, "DEFAULTKEY");
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER2);

            resetStatus();
        }
    }

    /**
     * Test that DEFAULTKEY is used if TESTKEY is missing.
     */
    @Test
    public void test03runServiceWithOnlyDefaultKey() {
        try {
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER1,
                    "DEFAULTKEY", "DefaultKey1");
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER2,
                    "DEFAULTKEY", "DefaultKey2");
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER1,
                    "TESTKEY");
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER2,
                    "TESTKEY");
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER2);

            setServiceActive(true);
            // make sure the service had time to run
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER1, WORKERID_CRYPTOWORKER2)
            );

            final String keyAlias1 = getDebugKeyAlias(WORKERID_CRYPTOWORKER1);
            final String keyAlias2 = getDebugKeyAlias(WORKERID_CRYPTOWORKER2);

            // check that the service has run and tested keys for both configured workers
            assertNotNull("testKey run on worker 1", keyAlias1);
            assertNotNull("testKey run on worker 2", keyAlias2);
            assertEquals("DEFAULTKEY alias used for worker 1",
                         "DefaultKey1", keyAlias1);
            assertEquals("DEFAULTKEY alias used for worker 2",
                         "DefaultKey2", keyAlias2);
        } finally {
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER1, "DEFAULTKEY");
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER2, "DEFAULTKEY");
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER1, "TESTKEY",
                    "TestKey1");
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER2, "TESTKEY",
                    "TestKey2");
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER2);

            resetStatus();
        }
    }

    /**
     * Test that when adding non-existing workers to the list,
     * the existing worker's keys are still being tested.
     * Also test that getFatalErrors() still gives errors about the missing
     * workers.
     */
    @Test
    public void test04runServiceWithNonExistingWorkers() throws Exception {
        try {
            workerSession.setWorkerProperty(WORKERID_SERVICE,
                    HSMKeepAliveTimedService.CRYPTOTOKENS,
                    "CryptoWorker1,CryptoWorker2,NonExistingWorker,9994711");
            workerSession.reloadConfiguration(WORKERID_SERVICE);

            final List<String> fatalErrors =
                    workerSession.getStatus(new WorkerIdentifier(WORKERID_SERVICE)).getFatalErrors();

            assertTrue("Should contain error: " + fatalErrors,
                    fatalErrors.contains("Invalid worker: Worker{name: NonExistingWorker}"));
            assertTrue("Should contain error: " + fatalErrors,
                    fatalErrors.contains("Invalid worker: Worker{id: 9994711}"));

            setServiceActive(true);
            // make sure the service had time to run
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER1, WORKERID_CRYPTOWORKER2)
            );

            final String keyAlias1 = getDebugKeyAlias(WORKERID_CRYPTOWORKER1);
            final String keyAlias2 = getDebugKeyAlias(WORKERID_CRYPTOWORKER2);

            // check that the service has run and tested keys for both configured workers
            assertNotNull("testKey run on worker 1", keyAlias1);
            assertNotNull("testKey run on worker 2", keyAlias2);
            assertEquals("TESTKEY alias used for worker 1",
                         "TestKey1", keyAlias1);
            assertEquals("TESTKEY alias used for worker 2",
                         "TestKey2", keyAlias2);
        } finally {
            workerSession.setWorkerProperty(WORKERID_SERVICE,
                    HSMKeepAliveTimedService.CRYPTOTOKENS,
                    "CryptoWorker1,CryptoWorker2");
            workerSession.reloadConfiguration(WORKERID_SERVICE);

            resetStatus();
        }
    }

    /**
     * Test that specifying crypto workers using worker IDs is working.
     */
    @Test
    public void test05runServiceWithWorkerIds() {
        try {
            workerSession.setWorkerProperty(WORKERID_SERVICE,
                    HSMKeepAliveTimedService.CRYPTOTOKENS, "5801,5802");
            workerSession.reloadConfiguration(WORKERID_SERVICE);

            setServiceActive(true);
            // make sure the service had time to run
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER1, WORKERID_CRYPTOWORKER2)
            );

            final String keyAlias1 = getDebugKeyAlias(WORKERID_CRYPTOWORKER1);
            final String keyAlias2 = getDebugKeyAlias(WORKERID_CRYPTOWORKER2);

            // check that the service has run and tested keys for both configured workers
            assertNotNull("testKey run on worker 1", keyAlias1);
            assertNotNull("testKey run on worker 2", keyAlias2);
            assertEquals("TESTKEY alias used for worker 1",
                         "TestKey1", keyAlias1);
            assertEquals("TESTKEY alias used for worker 2",
                         "TestKey2", keyAlias2);
        } finally {
            workerSession.setWorkerProperty(WORKERID_SERVICE,
                    HSMKeepAliveTimedService.CRYPTOTOKENS,
                    "CryptoWorker1,CryptoWorker2");
            workerSession.reloadConfiguration(WORKERID_SERVICE);

            resetStatus();
        }
    }

    /**
     * Test that having set both TESTKEY and DEFAULTKEY and failing testing
     * TESTKEY doesn't use DEFAULTKEY.
     */
    @Test
    public void test06runServiceWithDisabledTestKey() {
        try {
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER1,
                    "TESTKEY", "TestKey1");
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER1,
                    "DEFAULTKEY", "DefaultKey1");
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER1,
                    TestKeyDebugCryptoToken.DISABLE_TESTKEY, "true");
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER2,
                    "TESTKEY", "TestKey2");
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER2,
                    "DEFAULTKEY", "DefaultKey2");
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER2,
                    TestKeyDebugCryptoToken.DISABLE_TESTKEY, "true");
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER2);

            setServiceActive(true);
            // make sure the service had time to run
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER1, WORKERID_CRYPTOWORKER2)
            );

            final String keyAlias1 = getDebugKeyAlias(WORKERID_CRYPTOWORKER1);
            final String keyAlias2 = getDebugKeyAlias(WORKERID_CRYPTOWORKER2);

            // check that the service has run and didn't use simulated, non-existing key
            assertEquals("No key found", "_NoKey", keyAlias1);
            assertEquals("No key", "_NoKey", keyAlias2);
        } finally {
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER1,
                    "DEFAULTKEY");
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER1,
                    TestKeyDebugCryptoToken.DISABLE_TESTKEY);
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER2,
                    "DEFAULTKEY");
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER2,
                    TestKeyDebugCryptoToken.DISABLE_TESTKEY);
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER2);

            resetStatus();
        }
    }

    /**
     * Test with one crypto token with no key alias set.
     * Should still test the other token.
     */
    @Test
    public void test07runServiceOneCryptoTokenWithNoAlias() {
        try {
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER1,
                    HSMKeepAliveTimedService.TESTKEY);
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER1,
                    HSMKeepAliveTimedService.DEFAULTKEY);
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);

            setServiceActive(true);
            // make sure the service had time to run
            waitForServiceToRun(Collections.singletonList(WORKERID_CRYPTOWORKER2)
            );

            final String keyAlias1 = getDebugKeyAlias(WORKERID_CRYPTOWORKER1);
            final String keyAlias2 = getDebugKeyAlias(WORKERID_CRYPTOWORKER2);

            // check that the service has run and tested keys for the configured
            // worker
            assertNotNull("testKey run on worker 2", keyAlias2);
            assertEquals("TESTKEY alias used for worker 2",
                         "TestKey2", keyAlias2);

            // check that the service was not run for the worker with no
            // suitable alias
            assertNull("testKey not run on worker 1", keyAlias1);
        } finally {
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER1,
                    HSMKeepAliveTimedService.TESTKEY, "TestKey1");
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
            resetStatus();
        }
    }

    /**
     * Test that adding non-existing workers in front of the crypto token list,
     * execution is still continuing for existing workers.
     */
    @Test
    public void test08runServiceWithNonExistingWorkerBeforeExisting() throws Exception {
        try {
            workerSession.setWorkerProperty(WORKERID_SERVICE,
                    HSMKeepAliveTimedService.CRYPTOTOKENS,
                    "NonExistingWorker,9994711,CryptoWorker1,CryptoWorker2,");
            workerSession.reloadConfiguration(WORKERID_SERVICE);

            final List<String> fatalErrors =
                    workerSession.getStatus(new WorkerIdentifier(WORKERID_SERVICE)).getFatalErrors();

            assertTrue("Should contain error: " + fatalErrors,
                    fatalErrors.contains("Invalid worker: Worker{name: NonExistingWorker}"));
            assertTrue("Should contain error: " + fatalErrors,
                    fatalErrors.contains("Invalid worker: Worker{id: 9994711}"));

            setServiceActive(true);
            // make sure the service had time to run
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER1, WORKERID_CRYPTOWORKER2)
            );

            final String keyAlias1 = getDebugKeyAlias(WORKERID_CRYPTOWORKER1);
            final String keyAlias2 = getDebugKeyAlias(WORKERID_CRYPTOWORKER2);

            // check that the service has run and tested keys for both configured workers
            assertNotNull("testKey run on worker 1", keyAlias1);
            assertNotNull("testKey run on worker 2", keyAlias2);
            assertEquals("TESTKEY alias used for worker 1",
                         "TestKey1", keyAlias1);
            assertEquals("TESTKEY alias used for worker 2",
                         "TestKey2", keyAlias2);
        } finally {
            workerSession.setWorkerProperty(WORKERID_SERVICE,
                    HSMKeepAliveTimedService.CRYPTOTOKENS,
                    "CryptoWorker1,CryptoWorker2");
            workerSession.reloadConfiguration(WORKERID_SERVICE);
            resetStatus();
        }
    }

    @Test
    public void test99tearDownDatabase() {
        removeWorker(WORKERID_SERVICE);
        removeWorker(WORKERID_CRYPTOWORKER1);
        removeWorker(WORKERID_CRYPTOWORKER2);
    }
}
