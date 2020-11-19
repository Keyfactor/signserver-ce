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

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import org.signserver.testutils.WebTestCase;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for SignerStatusReportTimedService.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SignerStatusReportWorkerTest extends WebTestCase {

    /**
     * Worker id for the service.
     */
    private static final int WORKERID_WORKER = 5702;

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

    private static final int[] WORKERS = new int[] {WORKERID_WORKER, WORKERID_SIGNER1, WORKERID_SIGNER2, WORKERID_SIGNER3};

    private final SignerStatusReportParser parser = new SignerStatusReportParser();

    private final WorkerSession workerSession = getWorkerSession();

    @Override
    protected String getServletURL() {
        return "http://localhost:8080/signserver/process";
    }

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
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
        workerSession.setWorkerProperty(WORKERID_WORKER, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(WORKERID_WORKER, WorkerConfig.IMPLEMENTATION_CLASS,
            "org.signserver.module.signerstatusreport.SignerStatusReportWorker");

        workerSession.setWorkerProperty(WORKERID_WORKER, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(WORKERID_WORKER, "WORKERS",
                WORKER_SIGNER1+","+WORKER_SIGNER2+","+WORKER_SIGNER3);

        workerSession.reloadConfiguration(WORKERID_WORKER);
        workerSession.activateSigner(new WorkerIdentifier(WORKERID_SIGNER1), "foo123");
        workerSession.activateSigner(new WorkerIdentifier(WORKERID_SIGNER2), "foo123");
        workerSession.activateSigner(new WorkerIdentifier(WORKERID_SIGNER3), "foo123");
    }

    @Test
    public void test01Report() throws Exception {

        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", String.valueOf(WORKERID_WORKER));
        fields.put("data", "");
        HttpURLConnection conn = sendGet(getServletURL(), fields);


        Map<String, Map<String, String>> status;

        // Now all three workers should be present and ACTIVE
        InputStream in = null;
        try {
            in = conn.getInputStream();
            status = parser.parse(in);
        } finally {
            if (in != null) {
                in.close();
            }
        }

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


        // Now WORKER1 should be OFFLINE and the other as before
        conn = sendGet(getServletURL(), fields);
        try {
            in = conn.getInputStream();
            status = parser.parse(in);
        } finally {
            if (in != null) {
                in.close();
            }
        }

        assertNotNull("Worker 1 present", status.get(WORKER_SIGNER1));
        assertEquals("Worker 1 OFFLINE", "OFFLINE", status.get(WORKER_SIGNER1).get("status"));

        assertNotNull("Worker 2 present", status.get(WORKER_SIGNER2));
        assertEquals("Worker 2 active", "ACTIVE", status.get(WORKER_SIGNER2).get("status"));

        assertNotNull("Worker 3 present", status.get(WORKER_SIGNER3));
        assertEquals("Worker 3 active", "ACTIVE", status.get(WORKER_SIGNER3).get("status"));

        // test that there is no fatal errors before removing the WORKERS property
        WorkerStatus workerStatus = workerSession.getStatus(new WorkerIdentifier(WORKERID_WORKER));
        List<String> errors = workerStatus.getFatalErrors();
        assertTrue("No fatal errors: " + errors, errors.isEmpty());

        // test that removing the WORKERS property results in a fatal error
        workerSession.removeWorkerProperty(WORKERID_WORKER, "WORKERS");
        workerSession.reloadConfiguration(WORKERID_WORKER);
        workerStatus = workerSession.getStatus(new WorkerIdentifier(WORKERID_WORKER));
        errors = workerStatus.getFatalErrors();
        assertTrue("Should mention missing WORKERS property", errors.contains("Property WORKERS missing"));

        // restore
        workerSession.setWorkerProperty(WORKERID_WORKER, "WORKERS",
                WORKER_SIGNER1+","+WORKER_SIGNER2+","+WORKER_SIGNER3);
        workerSession.reloadConfiguration(WORKERID_WORKER);
    }

    /**
     * Removes all test workers.
     */
    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKERID_WORKER);
        for (int workerId : WORKERS) {
            removeWorker(workerId);
        }
    }

}
