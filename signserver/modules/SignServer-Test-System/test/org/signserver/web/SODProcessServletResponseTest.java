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

import java.util.HashMap;
import java.util.Map;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.module.mrtdsodsigner.MRTDSODSigner;

/**
 * Tests that the right HTTP status codes are returned in different situations.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class SODProcessServletResponseTest extends WebTestCase {
    
    private static final String KEYDATA = "KEYDATA";
    
    /** multipart/form-data is not supported by the SODProcessServlet. */
    private static final boolean SKIP_MULTIPART = true;

    @Override
    protected String getServletURL() {
        return "http://localhost:8080/signserver/sod";
    }

    /**
     * Sets up a dummy signer.
     * @throws Exception in case of error
     */
    public void test00SetupDatabase() throws Exception {
        addSigner(MRTDSODSigner.class.getName());
    }

    /**
     * Test that a successful request returns status code 200.
     */
    public void test01HttpStatus200() {
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("dataGroup1", "Yy==");
        fields.put("dataGroup2", "Yy==");
        fields.put("dataGroup3", "Yy==");
        fields.put("encoding", "base64");

        assertStatusReturned(fields, 200, SKIP_MULTIPART);
    }

    /**
     * Test that a bad request returns status code 400.
     * This request misses the "data" field.
     */
    public void test02HttpStatus400_missingField() {
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", getSignerNameDummy1());
        // Notice: No datagrou fields added
        fields.put("encoding", "base64");

        assertStatusReturned(fields, 400, SKIP_MULTIPART);
    }

    /**
     * Test that a bad request returns status code 400.
     * This request contains an unknown LDS version.
     */
    public void test02HttpStatus400_unknownLdsVersion() {
        final String unknownLdsVersion = "9999";
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerId", String.valueOf(getSignerIdDummy1()));
        fields.put("dataGroup1", "Yy==");
        fields.put("dataGroup2", "Yy==");
        fields.put("dataGroup3", "Yy==");
        fields.put("encoding", "base64");
        fields.put("ldsVersion", unknownLdsVersion);

        assertStatusReturned(fields, 400, SKIP_MULTIPART);
    }

    /**
     * Test that a request for non-existing worker returns status code 404.
     */
    public void test03HttpStatus404_nonExistingName() {
        final String nonExistingWorker = "_NotExistingWorker123_";
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", nonExistingWorker);
        fields.put("dataGroup1", "Yy==");
        fields.put("dataGroup2", "Yy==");
        fields.put("dataGroup3", "Yy==");
        fields.put("encoding", "base64");

        assertStatusReturned(fields, 404, SKIP_MULTIPART);
    }

    /**
     * Test that a request for non-existing worker returns status code 404.
     */
    public void test03HttpStatus404_nonExistingId() {
        final int nonExistingId = 0;
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerId", String.valueOf(nonExistingId));
        fields.put("dataGroup1", "Yy==");
        fields.put("dataGroup2", "Yy==");
        fields.put("dataGroup3", "Yy==");
        fields.put("encoding", "base64");

        assertStatusReturned(fields, 404, SKIP_MULTIPART);
    }

    /**
     * Test that when the cryptotoken is offline the status code is 503.
     */
    public void test04HttpStatus503() {
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("dataGroup1", "Yy==");
        fields.put("dataGroup2", "Yy==");
        fields.put("dataGroup3", "Yy==");
        fields.put("encoding", "base64");

        try {
            // Deactivate crypto token
            try {
                getWorkerSession().deactivateSigner(getSignerIdDummy1());
            } catch (CryptoTokenOfflineException ex) {
                fail(ex.getMessage());
            } catch (InvalidWorkerIdException ex) {
                fail(ex.getMessage());
            }

            assertStatusReturned(fields, 503, SKIP_MULTIPART);
        } finally {
            // Activat crypto token
            try {
                getWorkerSession().activateSigner(getSignerIdDummy1(), "");
            } catch (CryptoTokenAuthenticationFailureException ex) {
                fail(ex.getMessage());
            } catch (CryptoTokenOfflineException ex) {
                fail(ex.getMessage());
            } catch (InvalidWorkerIdException ex) {
                fail(ex.getMessage());
            }
        }
    }

    /**
     * Test that when an exception occurs status code 500 is returned.
     */
    public void test05HttpStatus500_exception() {
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("dataGroup1", "Yy==");
        fields.put("dataGroup2", "Yy==");
        fields.put("dataGroup3", "Yy==");
        fields.put("encoding", "base64");

        // Set any bad properties that will make the signer fail with an exception
        final String originalKeyData = getWorkerSession().getCurrentWorkerConfig(
                getSignerIdDummy1()).getProperty(KEYDATA);
        final String badKeyData = "_any-bad-key-data_";
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), KEYDATA,
                badKeyData);
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());

        try {
            assertStatusReturned(fields, 500, SKIP_MULTIPART);
        } finally {
            // Restore KEYDATA
            getWorkerSession().setWorkerProperty(getSignerIdDummy1(), KEYDATA,
                    originalKeyData);
            getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        }
    }

    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
    }
}
