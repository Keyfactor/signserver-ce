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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.ServiceConfig;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.ModulesTestCase;

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

    private final IWorkerSession workerSession = getWorkerSession();

    private File signServerHome;
    
    @Before
    @Override
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        signServerHome = getSignServerHome();
        deleteDebugFile(WORKERID_CRYPTOWORKER1);
        deleteDebugFile(WORKERID_CRYPTOWORKER2);
    }
    
    private File getDebugFile(final int workerId) {
        return new File(signServerHome,
                         "~testkey-" + workerId);
    }
    
    private void deleteDebugFile(final int workerId) {
        final File debugFile = getDebugFile(workerId);

        debugFile.delete();
    }
    
    private boolean debugFileExists(final int workerId) {
        final File debugFile = getDebugFile(workerId);

        return debugFile.exists() && debugFile.isFile();
    }
    
    private void waitForServiceToRun(final Collection<Integer> workerIds,
            final int maxTries) {
         try {
            for (int i = 0; i < maxTries; i++) {
                boolean missingFile = false;
                
                for (final int workerId : workerIds) {
                    if (!debugFileExists(workerId)) {
                        missingFile = true;
                        break;
                    }
                }
                
                if (!missingFile) {
                    break;
                }
                Thread.sleep(1000);
            }
        } catch (InterruptedException ex) {
            LOG.error("Interrupted", ex);
        }
    }
    
    private String getDebugKeyAlias(final int workerId) {
        final File debugFile = getDebugFile(workerId);
 
        try {
            final FileInputStream fis = new FileInputStream(debugFile);
            
            return IOUtils.toString(fis);
        } catch (FileNotFoundException e) {
            return null;
        } catch (IOException e) {
            LOG.error("Error reading debug file: " + e.getMessage());
            return null;
        }
    }
    
    private void setServiceActive(final boolean active) {
        workerSession.setWorkerProperty(WORKERID_SERVICE, ServiceConfig.ACTIVE,
                Boolean.valueOf(active).toString());
        workerSession.reloadConfiguration(WORKERID_SERVICE);
    }
   
    public void test00setupDatabase() throws Exception {
        setProperties(new File(getSignServerHome(), "res/test/test-hsmkeepalive-configuration.properties"));
        
        // set debug outpaths
        workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER1,
                TestKeyDebugCryptoToken.TESTKEY_DEBUG_OUTPATH,
                getDebugFile(WORKERID_CRYPTOWORKER1).getAbsolutePath());
        workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER2,
                TestKeyDebugCryptoToken.TESTKEY_DEBUG_OUTPATH,
                getDebugFile(WORKERID_CRYPTOWORKER2).getAbsolutePath());
        
        
        workerSession.reloadConfiguration(WORKERID_SERVICE);
        workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
        workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER2);
    }
    
    /**
     * Test a basic configuration with two crypto workers set up with the
     * TESTKEY key alias property.
     * 
     * @throws Exception 
     */
    public void test01runServiceWithTwoWorkers() throws Exception {
        try {
            setServiceActive(true);
            // make sure the service had time to run
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER1, WORKERID_CRYPTOWORKER2),
                30);
            // check that the service has run and tested keys for both configured workers
            assertTrue("testKey run on worker 1",
                        debugFileExists(WORKERID_CRYPTOWORKER1));
            assertTrue("testKey run on worker 2",
                        debugFileExists(WORKERID_CRYPTOWORKER2));
            assertEquals("TESTKEY alias used for worker 1",
                         "TestKey1", getDebugKeyAlias(WORKERID_CRYPTOWORKER1));
            assertEquals("TESTKEY alias used for worker 2",
                         "TestKey2", getDebugKeyAlias(WORKERID_CRYPTOWORKER2));
        } finally {
            setServiceActive(false);
            deleteDebugFile(WORKERID_CRYPTOWORKER1);
            deleteDebugFile(WORKERID_CRYPTOWORKER2);
        }
    }
    
    /**
     * Test that when setting DEFAULTKEY, TESTKEY is still used.
     * 
     * @throws Exception 
     */
    public void test02runServiceWithTestAndDefaultKey() throws Exception {
        try {
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER1,
                    "DEFAULTKEY", "DefaultKey1");
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER2,
                    "DEFAULTKEY", "DefaultKey2");
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER2);
            
            setServiceActive(true);
            // make sure the service had time to run
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER1, WORKERID_CRYPTOWORKER2),
                    30);
            // check that the service has run and tested keys for both configured workers
            assertTrue("testKey run on worker 1",
                        debugFileExists(WORKERID_CRYPTOWORKER1));
            assertTrue("testKey run on worker 2",
                        debugFileExists(WORKERID_CRYPTOWORKER2));
            assertEquals("TESTKEY alias used for worker 1",
                         "TestKey1", getDebugKeyAlias(WORKERID_CRYPTOWORKER1));
            assertEquals("TESTKEY alias used for worker 2",
                         "TestKey2", getDebugKeyAlias(WORKERID_CRYPTOWORKER2));
        } finally {
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER1, "DEFAULTKEY");
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER2, "DEFAULTKEY");
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER2);

            setServiceActive(false);
            deleteDebugFile(WORKERID_CRYPTOWORKER1);
            deleteDebugFile(WORKERID_CRYPTOWORKER2);
        }
    }
    
    /**
     * Test that DEFAULTKEY is used if TESTKEY is missing.
     * 
     * @throws Exception 
     */
    public void test03runServiceWithOnlyDefaultKey() throws Exception {
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
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER1, WORKERID_CRYPTOWORKER2),
                    30);
            // check that the service has run and tested keys for both configured workers
            assertTrue("testKey run on worker 1",
                        debugFileExists(WORKERID_CRYPTOWORKER1));
            assertTrue("testKey run on worker 2",
                        debugFileExists(WORKERID_CRYPTOWORKER2));
            assertEquals("DEFAULTKEY alias used for worker 1",
                         "DefaultKey1", getDebugKeyAlias(WORKERID_CRYPTOWORKER1));
            assertEquals("DEFAULTKEY alias used for worker 2",
                         "DefaultKey2", getDebugKeyAlias(WORKERID_CRYPTOWORKER2));
        } finally {
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER1, "DEFAULTKEY");
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER2, "DEFAULTKEY");
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER1, "TESTKEY",
                    "TestKey1");
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER2, "TESTKEY",
                    "TestKey2");
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER2);

            setServiceActive(false);
            deleteDebugFile(WORKERID_CRYPTOWORKER1);
            deleteDebugFile(WORKERID_CRYPTOWORKER2);
        }
    }
    
    /**
     * Test that when adding non-existing workers to the list,
     * the existing worker's keys are still being tested.
     * Also test that getFatalErrors() still gives errors about the missing
     * workers.
     * 
     * @throws Exception 
     */
    public void test04runServiceWithNonExistingWorkers() throws Exception {
        try {
            workerSession.setWorkerProperty(WORKERID_SERVICE,
                    HSMKeepAliveTimedService.CRYPTOTOKENS,
                    "CryptoWorker1,CryptoWorker2,NonExistingWorker,9994711");
            workerSession.reloadConfiguration(WORKERID_SERVICE);
            
            final List<String> fatalErrors =
                    workerSession.getStatus(WORKERID_SERVICE).getFatalErrors();
            
            assertTrue("Should contain error",
                    fatalErrors.contains("No such worker: NonExistingWorker"));
            assertTrue("Should contain error",
                    fatalErrors.contains("Invalid worker ID: 9994711"));
            
            setServiceActive(true);
            // make sure the service had time to run
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER1, WORKERID_CRYPTOWORKER2),
                    30);
            // check that the service has run and tested keys for both configured workers
            assertTrue("testKey run on worker 1",
                        debugFileExists(WORKERID_CRYPTOWORKER1));
            assertTrue("testKey run on worker 2",
                        debugFileExists(WORKERID_CRYPTOWORKER2));
            assertEquals("TESTKEY alias used for worker 1",
                         "TestKey1", getDebugKeyAlias(WORKERID_CRYPTOWORKER1));
            assertEquals("TESTKEY alias used for worker 2",
                         "TestKey2", getDebugKeyAlias(WORKERID_CRYPTOWORKER2));
        } finally {
            workerSession.setWorkerProperty(WORKERID_SERVICE,
                    HSMKeepAliveTimedService.CRYPTOTOKENS,
                    "CryptoWorker1,CryptoWorker2");
            workerSession.reloadConfiguration(WORKERID_SERVICE);
            setServiceActive(false);
            deleteDebugFile(WORKERID_CRYPTOWORKER1);
            deleteDebugFile(WORKERID_CRYPTOWORKER2);
        }
    }
    
    /**
     * Test that specifying crypto workers using worker IDs is working.
     * 
     * @throws Exception 
     */
    public void test05runServiceWithWorkerIds() throws Exception {
        try {
            workerSession.setWorkerProperty(WORKERID_SERVICE,
                    HSMKeepAliveTimedService.CRYPTOTOKENS, "5801,5802");
            workerSession.reloadConfiguration(WORKERID_SERVICE);
            
            setServiceActive(true);
            // make sure the service had time to run
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER1, WORKERID_CRYPTOWORKER2),
                    30);
            // check that the service has run and tested keys for both configured workers
            assertTrue("testKey run on worker 1",
                        debugFileExists(WORKERID_CRYPTOWORKER1));
            assertTrue("testKey run on worker 2",
                        debugFileExists(WORKERID_CRYPTOWORKER2));
            assertEquals("TESTKEY alias used for worker 1",
                         "TestKey1", getDebugKeyAlias(WORKERID_CRYPTOWORKER1));
            assertEquals("TESTKEY alias used for worker 2",
                         "TestKey2", getDebugKeyAlias(WORKERID_CRYPTOWORKER2));
        } finally {
            workerSession.setWorkerProperty(WORKERID_SERVICE,
                    HSMKeepAliveTimedService.CRYPTOTOKENS,
                    "CryptoWorker1,CryptoWorker2");
            workerSession.reloadConfiguration(WORKERID_SERVICE);
            setServiceActive(false);
            deleteDebugFile(WORKERID_CRYPTOWORKER1);
            deleteDebugFile(WORKERID_CRYPTOWORKER2);
        }
    }
    
    /**
     * Test that having set both TESTKEY and DEFAULTKEY and failing testing
     * TESTKEY doesn't use DEFAULTKEY.
     * 
     * @throws Exception 
     */
    public void test06runServiceWithDisabledTestKey() throws Exception {
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
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER1, WORKERID_CRYPTOWORKER2),
                    30);
            // check that the service has run and didn't use simulated, non-existing key
            assertEquals("No key found",
                         "_NoKey", getDebugKeyAlias(WORKERID_CRYPTOWORKER1));
            assertEquals("No key",
                         "_NoKey", getDebugKeyAlias(WORKERID_CRYPTOWORKER2));
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
            
            setServiceActive(false);
            deleteDebugFile(WORKERID_CRYPTOWORKER1);
            deleteDebugFile(WORKERID_CRYPTOWORKER2);
        }
    }
    
    /**
     * Test with one crypto token with no key alias set.
     * Should still test the other token.
     * 
     * @throws Exception 
     */
    public void test07runServiceOneCryptoTokenWithNoAlias() throws Exception {
        try {
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER1,
                    HSMKeepAliveTimedService.TESTKEY);
            workerSession.removeWorkerProperty(WORKERID_CRYPTOWORKER1,
                    HSMKeepAliveTimedService.DEFAULTKEY);
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
            
            setServiceActive(true);
            // make sure the service had time to run
            waitForServiceToRun(Arrays.asList(WORKERID_CRYPTOWORKER2),
                30);
            // check that the service has run and tested keys for both configured workers
            assertTrue("testKey run on worker 2",
                        debugFileExists(WORKERID_CRYPTOWORKER2));
            assertEquals("TESTKEY alias used for worker 2",
                         "TestKey2", getDebugKeyAlias(WORKERID_CRYPTOWORKER2));
        } finally {
            workerSession.setWorkerProperty(WORKERID_CRYPTOWORKER1,
                    HSMKeepAliveTimedService.TESTKEY, "TestKey1");
            workerSession.reloadConfiguration(WORKERID_CRYPTOWORKER1);
            setServiceActive(false);
            deleteDebugFile(WORKERID_CRYPTOWORKER1);
            deleteDebugFile(WORKERID_CRYPTOWORKER2);
        }
    }
    
    public void test99tearDownDatabase() throws Exception {
        removeWorker(WORKERID_SERVICE);
        removeWorker(WORKERID_CRYPTOWORKER1);
        removeWorker(WORKERID_CRYPTOWORKER2);
    } 
}
