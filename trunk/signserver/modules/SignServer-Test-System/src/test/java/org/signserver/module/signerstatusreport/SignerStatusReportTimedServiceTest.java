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
package org.signserver.module.signerstatusreport;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerType;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.testutils.ModulesTestCase;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests for SignerStatusReportTimedService.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SignerStatusReportTimedServiceTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(SignerStatusReportTimedServiceTest.class);

    /**
     * Worker id for the service.
     */
    private static final int WORKERID_SERVICE = 5701;

    /**
     * WORKERID used in this test case as defined in
     * junittest-part-config.properties.
     */
    private static final int WORKERID_SIGNER1 = 5681;
    private static final String WORKER_SIGNER1 = "TestXMLSigner81";

    /**
     * WORKERID used in this test case as defined in
     * junittest-part-config.properties.
     */
    private static final int WORKERID_SIGNER2 = 5682;
    private static final String WORKER_SIGNER2 = "TestXMLSigner82";

    /**
     * WORKERID used in this test case as defined in
     * junittest-part-config.properties.
     */
    private static final int WORKERID_SIGNER3 = 5676;
    private static final String WORKER_SIGNER3 = "TestXMLSigner";

    private static final int[] WORKERS = new int[] {WORKERID_SERVICE, WORKERID_SIGNER1, WORKERID_SIGNER2, WORKERID_SIGNER3};

    private static final long serviceInterval = 10;

    private static File outputFile;

    private final SignerStatusReportParser parser = new SignerStatusReportParser();

    private final WorkerSession workerSession = getWorkerSession();

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();

        outputFile = new File(getSignServerHome() + File.separator
                + "~test-outputfile.dat");
        if (outputFile.exists()) {
            if (!outputFile.delete()) {
                fail("Could not remove: " + outputFile.getAbsolutePath());
            }
        }
    }

    /**
     * Create test workers.
     */
    @Test
    public void test00SetupDatabase() throws Exception {
        addDummySigner(WORKERID_SIGNER1, WORKER_SIGNER1, false);
        addDummySigner(WORKERID_SIGNER2, WORKER_SIGNER2, false);
        addDummySigner(WORKERID_SIGNER3, WORKER_SIGNER3, false);

        // Setup service
        workerSession.setWorkerProperty(WORKERID_SERVICE, WorkerConfig.TYPE, WorkerType.TIMED_SERVICE.name());
        workerSession.setWorkerProperty(WORKERID_SERVICE, WorkerConfig.IMPLEMENTATION_CLASS,
            "org.signserver.module.signerstatusreport.SignerStatusReportTimedService");

        workerSession.setWorkerProperty(WORKERID_SERVICE, "WORKERS",
                WORKER_SIGNER1+","+WORKER_SIGNER2+","+WORKER_SIGNER3);
        workerSession.setWorkerProperty(WORKERID_SERVICE, "OUTPUTFILE",
                outputFile.getAbsolutePath());
        workerSession.setWorkerProperty(WORKERID_SERVICE, "INTERVAL",
                String.valueOf(serviceInterval));
        workerSession.setWorkerProperty(WORKERID_SERVICE, "ACTIVE", "FALSE");

        workerSession.reloadConfiguration(WORKERID_SERVICE);
        workerSession.activateSigner(new WorkerIdentifier(WORKERID_SIGNER1), "foo123");
        workerSession.activateSigner(new WorkerIdentifier(WORKERID_SIGNER2), "foo123");
        workerSession.activateSigner(new WorkerIdentifier(WORKERID_SIGNER3), "foo123");
    }

    @Test
    public void test01Report() throws Exception {
        if (outputFile.exists()) {
            assertTrue("Removed outputfile", outputFile.delete());
        }

        // Enable service
        workerSession.setWorkerProperty(WORKERID_SERVICE, "ACTIVE", "TRUE");
        workerSession.reloadConfiguration(WORKERID_SERVICE);

        waitForServiceRun();

        Map<String, Map<String, String>> status;

        // Now all three workers should be present and ACTIVE
        status = parser.parseOutputFile(outputFile);

        assertNotNull("Worker 1 present", status.get(WORKER_SIGNER1));
        assertEquals("Worker 1 active", "ACTIVE", status.get(WORKER_SIGNER1).get("status"));
        assertNotNull("Worker 1 signings", status.get(WORKER_SIGNER1).get("signings"));

        assertNotNull("Worker 2 present", status.get(WORKER_SIGNER2));
        assertEquals("Worker 2 active", "ACTIVE", status.get(WORKER_SIGNER2).get("status"));
        assertNotNull("Worker 2 signings", status.get(WORKER_SIGNER2).get("signings"));

        assertNotNull("Worker 3 present", status.get(WORKER_SIGNER3));
        assertEquals("Worker 3 active", "ACTIVE", status.get(WORKER_SIGNER3).get("status"));
        assertNotNull("Worker 3 signings", status.get(WORKER_SIGNER3).get("signings"));

        // Disable one worker and check the result
//        workerSession.setWorkerProperty(WORKERID_SIGNER1, "DISABLED", "TRUE");
//        workerSession.reloadConfiguration(WORKERID_SIGNER1);
        workerSession.deactivateSigner(new WorkerIdentifier(WORKERID_SIGNER1));

        outputFile.delete();

        waitForServiceRun();

        // Now WORKER1 should be OFFLINE and the other as before
        try {
            status = parser.parseOutputFile(outputFile);
        } catch (FileNotFoundException ex) {
            fail("FileNotFound: " + ex.getMessage());
        } catch (IOException ex) {
            fail("IOException: " + ex.getMessage());
        }



        assertNotNull("Worker 1 present", status.get(WORKER_SIGNER1));
        assertEquals("Worker 1 OFFLINE", "OFFLINE", status.get(WORKER_SIGNER1).get("status"));

        assertNotNull("Worker 2 present", status.get(WORKER_SIGNER2));
        assertEquals("Worker 2 active", "ACTIVE", status.get(WORKER_SIGNER2).get("status"));
        assertNotNull("Worker 2 signings", status.get(WORKER_SIGNER2).get("signings"));

        assertNotNull("Worker 3 present", status.get(WORKER_SIGNER3));
        assertEquals("Worker 3 active", "ACTIVE", status.get(WORKER_SIGNER3).get("status"));
        assertNotNull("Worker 3 signings", status.get(WORKER_SIGNER3).get("signings"));

        // test that there are no fatal errors before removing required properties
        WorkerStatus workerStatus = workerSession.getStatus(new WorkerIdentifier(WORKERID_SERVICE));
        List<String> errors = workerStatus.getFatalErrors();
        assertTrue("No fatal errors", errors.isEmpty());

        // test that removing the WORKERS and OUTPUTFILE property results in a fatal error
        workerSession.removeWorkerProperty(WORKERID_SERVICE, "WORKERS");
        workerSession.removeWorkerProperty(WORKERID_SERVICE, "OUTPUTFILE");
        workerSession.reloadConfiguration(WORKERID_SERVICE);

        workerStatus = workerSession.getStatus(new WorkerIdentifier(WORKERID_SERVICE));
        errors = workerStatus.getFatalErrors();
        assertTrue("Should mention missing WORKERS property", errors.contains("Property WORKERS missing"));
        assertTrue("Should mention missing OUTPUTFILE property", errors.contains("Property OUTPUTFILE missing"));

        // restore
        workerSession.setWorkerProperty(WORKERID_SERVICE, "WORKERS",
                WORKER_SIGNER1+","+WORKER_SIGNER2+","+WORKER_SIGNER3);
        workerSession.setWorkerProperty(WORKERID_SERVICE, "OUTPUTFILE",
                outputFile.getAbsolutePath());
        workerSession.reloadConfiguration(WORKERID_SERVICE);
    }

    /**
     * Removes all test workers.
     */
    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKERID_SERVICE);
        for (int workerId : WORKERS) {
            removeWorker(workerId);
        }
    }



    private static void waitForServiceRun() {
        try {
            for (int i = 0; i < 30; i++) {
                if (outputFile.exists()) {
                    break;
                }
                Thread.sleep(1000);
            }
        } catch (InterruptedException ex) {
            LOG.error("Interrupted", ex);
        }
    }

}
