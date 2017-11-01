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
package org.signserver.web;

import org.signserver.testutils.WebTestCase;
import java.util.HashMap;
import java.util.Map;

import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.module.mrtdsodsigner.MRTDSODSigner;

import org.junit.Test;
import org.signserver.common.WorkerIdentifier;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests that the right HTTP status codes are returned in different situations.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SODProcessWorkerServletResponseTest extends WebTestCase {

    /** multipart/form-data is not supported by the SODProcessServlet. */
    private static final boolean SKIP_MULTIPART = true;
    
    private final static String UNEXISTING_WORKER_NAME = "_NotExistingWorker123_";
    private final static int UNEXISTING_WORKER_ID = 4711;

    private String currentWorkerName = null;
    private boolean trailingSlash = true; // insert a trailing / after the base URI
    private boolean extraSlashBeforeWorkerName = false;
                                                                              // set to true to generate an extra
                                                                              // slash before the worker name
    private boolean extraSlashBeforeServletName = false;
                                                                              // set to true to generate an extra
                                                                              // slash before the servlet name

    @Override
    protected String getServletURL() {
        return getPreferredHTTPProtocol() + getHTTPHost() + ":" +
                                getPreferredHTTPPort() + "/signserver/" +
				(extraSlashBeforeServletName ? "/" : "") +
				"sodworker" + (trailingSlash ? "/" : "") +
				(extraSlashBeforeWorkerName ? "/" : "" ) +
				currentWorkerName;
    }

    /**
     * Sets up a dummy signer.
     * @throws Exception in case of error
     */
    @Test
    public void test00SetupDatabase() throws Exception {
        addSigner(MRTDSODSigner.class.getName(), false);
        addSigner("org.signserver.server.signers.EchoRequestMetadataSigner", 123, "DummySigner123", true);
        getWorkerSession().activateSigner(new WorkerIdentifier(getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);
    }

    private void assertStatusReturned(final Map<String, String> fields,
            final int expectedStatus, final String workerName,
            final boolean trailingSlash,
            final boolean extraSlashBeforeWorkerName,
            final boolean extraSlashBeforeServletName) {
        this.currentWorkerName = workerName;
        this.trailingSlash = trailingSlash;
        this.extraSlashBeforeWorkerName = extraSlashBeforeWorkerName;
        this.extraSlashBeforeServletName = extraSlashBeforeServletName;
        
        assertStatusReturned(fields, expectedStatus, SKIP_MULTIPART);
    }
    
    /**
     * Test that a successful request returns status code 200.
     */
    @Test
    public void test01HttpStatus200() {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");
    
        assertStatusReturned(fields, 200, getSignerNameDummy1(), true, false,
                false);
    }

    
    /**
     * Test correct request, overriding an unexisting worker name set by a request
     * parameter
     */
    @Test
    public void test02HttpStatus200_overrideRequestParamWorkerName() {
        Map<String, String> fields = new HashMap<>();
        
        fields.put("workerName", UNEXISTING_WORKER_NAME);
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");

        assertStatusReturned(fields, 200, getSignerNameDummy1(), true, false,
                false);
    }
    
    /**
     * Test correct request, overriding an unexisting worker ID set by a request
     * parameter.
     */
    @Test
    public void test03HttpStatus200_overrideRequestParamWorkerId() {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", String.valueOf(UNEXISTING_WORKER_ID));
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");

        assertStatusReturned(fields, 200, getSignerNameDummy1(), true, false,
                false);
    }
    
    /**
     * Test with incorrect worker name in the URL.
     */
    @Test
    public void test04HttpStatus404() {
        Map<String, String> fields = new HashMap<>();
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");
        
        assertStatusReturned(fields, 404, UNEXISTING_WORKER_NAME, true, false,
                false);
    }
    
    /**
     * Test with incorrect worker name in the URL.
     * Set an existing worker name using request parameter.
     * The name used in the URL should override the request parameter and result
     * in a 404.
     */
    @Test
    public void test05HttpStatus404_setCorrectWorkerNameRequestParam() {
        Map<String, String> fields = new HashMap<>();
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");
        fields.put("workerName", getSignerNameDummy1());

        assertStatusReturned(fields, 404, UNEXISTING_WORKER_NAME, true, false,
                false);
    }
    
    /**
     * Test with incorrect worker name in the URL.
     * Set an existing worker ID using request parameter.
     * The name used in the URL should override the request parameter and result
     * in a 404.
     */
    @Test
    public void test06HttpStatus404_setCorrectWorkerIdRequestParam() {
        Map<String, String> fields = new HashMap<>();
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");
        fields.put("workerName", getSignerNameDummy1());
        fields.put("workerId", String.valueOf(getSignerIdDummy1()));

        assertStatusReturned(fields, 404, UNEXISTING_WORKER_NAME, true, false,
                false);
    }
    
    /**
     * Test with incorrect worker name in the URL.
     * Set an existing worker name and ID using request parameter.
     * The name used in the URL should override the request parameter and result
     * in a 404.
     */
    @Test
    public void test07HttpStatus404_setCorrectWorkerIdAndNameRequestParam() {
        Map<String, String> fields = new HashMap<>();
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");
        fields.put("workerId", String.valueOf(getSignerIdDummy1()));
        fields.put("workerName", getSignerNameDummy1());

        assertStatusReturned(fields, 404, UNEXISTING_WORKER_NAME, true, false,
                false);
    }
    
    /**
     * Test with an incomplete worker URI on the form /signserver/worker
     * this shall fail with a status 404
     */
    @Test
    public void test08HttpStatus404_emptyWorkerName() {
        Map<String, String> fields = new HashMap<>();
        fields.put("data", "<root/>");
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");

        assertStatusReturned(fields, 404, "", true, false, false);
    }
    
    /**
     * Test with an incomplete worker URI on the form /signserver/sod/worker/
     * with a valid worker name supplied via a request parameter
     * this shall (still) fail with a status 404
     */
    @Test
    public void test09HttpStatus404_emptyWorkerNameWithWorkerNameRequestParam() {
        Map<String, String> fields = new HashMap<>();
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");
        fields.put("workerName", getSignerNameDummy1());

        assertStatusReturned(fields, 404, "", true, false, false);
    }
    
    /**
     * Test with an incomplete worker URI on the form /signserver/sod/worker/
     * with a valid worker ID supplied via a request parameter
     * this shall (still) fail with a status 404
     */
    @Test
    public void test10HttpStatus404_emptyWorkerNameWithWorkerIdRequestParam() {
        Map<String, String> fields = new HashMap<>();
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");
        fields.put("workerId", String.valueOf(getSignerIdDummy1()));

        assertStatusReturned(fields, 404, "", true, false, false);
    }

    /**
     * Test with an incomplete worker URI on the form /signserver/sod/worker
     * (without the trailing /)
     * This shall fail with a 404
     */
    @Test
    public void test11HttpStatus404_emptyWorkerNameNoSlash() {
        Map<String, String> fields = new HashMap<>();
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");

        assertStatusReturned(fields, 404, "", false, false, false);
    }
    
    /**
     * Test with an incomplete worker URI on the form /signserver/sod/worker
     * (without the trailing /)
     * with a valid worker name given as a request parameters
     * This shall fail with a 404
     */
    @Test
    public void test12HttpStatus404_emptyWorkerNameNoSlashWithWorkerNameRequestParam() {
        Map<String, String> fields = new HashMap<>();
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");
        fields.put("workerName", getSignerNameDummy1());

        assertStatusReturned(fields, 404, "", false, false, false);
    }
    
    /**
     * Test with an incomplete worker URI on the form /signserver/sod/worker
     * (without the trailing /)
     * This shall fail with a 404
     */
    @Test
    public void test13HttpStatus404_emptyWorkerNameNoSlashWithWorkerIdRequestParam() {
        Map<String, String> fields = new HashMap<>();
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");
        fields.put("workerId", String.valueOf(getSignerIdDummy1()));

        assertStatusReturned(fields, 404, "", false, false, false);
    }
    
    /**
     * Test an invalid URL of the form /signserver/sod/worker//<worker name>
     * This shall fail with a 404
     */
    @Test
    public void test14HttpStatus404_extraSlashBeforeWorkerName() {
        Map<String, String> fields = new HashMap<>();
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");

        assertStatusReturned(fields, 404, getSignerNameDummy1(), true, true,
                false);
    }
    
    /**
     * Test a URL of the form /signserver//sod/worker/<worker name>
     * with an invalid worker name, but with a valid worker name given by a
     * request parameter.
     * This should fail with a 404 (it should not "fall through" to the general
     * processing in this case).
     */
    @Test
    public void test15HttpStatus404_extraSlashBeforeServletName() {
        Map<String, String> fields = new HashMap<>();
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup3", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("encoding", "base64");
        fields.put("workerName", getSignerNameDummy1());
        
        assertStatusReturned(fields, 404, UNEXISTING_WORKER_NAME, true, false,
                true);
    }
    
    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
        removeWorker(123);
    }
}
