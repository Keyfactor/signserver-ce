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
import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.module.mrtdsodsigner.MRTDSODSigner;

import org.junit.Test;
import org.signserver.common.WorkerIdentifier;
import org.signserver.testutils.ModulesTestCase;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Tests that the right HTTP status codes are returned in different situations.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SODProcessServletResponseTest extends WebTestCase {

    /** multipart/form-data is not supported by the SODProcessServlet. */
    private static final boolean SKIP_MULTIPART = true;

    @Override
    protected String getServletURL() {
        return getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver/sod";
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

    /**
     * Test that a successful request returns status code 200.
     */
    @Test
    public void test01HttpStatus200() {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "BTfUgfc6dXM0MoBS2jr5YmztlwKOILhJ9hFcIs12UZc=");
        fields.put("dataGroup3", "idxq5/Bqn0a1Za8D6rDs4L9gJNNlm346HQNXPP6wtZ0=");
        fields.put("encoding", "base64");

        assertStatusReturned(fields, 200, SKIP_MULTIPART);
    }

    /**
     * Test that a bad request returns status code 400.
     * This request misses the "data" field.
     */
    @Test
    public void test02HttpStatus400_missingField() {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getSignerNameDummy1());
        // Notice: No datagrou fields added
        fields.put("encoding", "base64");

        assertStatusReturned(fields, 400, SKIP_MULTIPART);
    }

    /**
     * Test that a bad request returns status code 400.
     * This request contains an unknown LDS version.
     */
    @Test
    public void test02HttpStatus400_unknownLdsVersion() {
        final String unknownLdsVersion = "9999";
        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", String.valueOf(getSignerIdDummy1()));
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "BTfUgfc6dXM0MoBS2jr5YmztlwKOILhJ9hFcIs12UZc=");
        fields.put("dataGroup3", "idxq5/Bqn0a1Za8D6rDs4L9gJNNlm346HQNXPP6wtZ0=");
        fields.put("encoding", "base64");
        fields.put("ldsVersion", unknownLdsVersion);

        assertStatusReturned(fields, 400, SKIP_MULTIPART);
    }

    /**
     * Test that a request for non-existing worker returns status code 404.
     */
    @Test
    public void test03HttpStatus404_nonExistingName() {
        final String nonExistingWorker = "_NotExistingWorker123_";
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", nonExistingWorker);
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "BTfUgfc6dXM0MoBS2jr5YmztlwKOILhJ9hFcIs12UZc=");
        fields.put("dataGroup3", "idxq5/Bqn0a1Za8D6rDs4L9gJNNlm346HQNXPP6wtZ0=");
        fields.put("encoding", "base64");

        assertStatusReturned(fields, 404, SKIP_MULTIPART);
    }

    /**
     * Test that a request for non-existing worker returns status code 404.
     */
    @Test
    public void test03HttpStatus404_nonExistingId() {
        final int nonExistingId = 0;
        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", String.valueOf(nonExistingId));
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "BTfUgfc6dXM0MoBS2jr5YmztlwKOILhJ9hFcIs12UZc=");
        fields.put("dataGroup3", "idxq5/Bqn0a1Za8D6rDs4L9gJNNlm346HQNXPP6wtZ0=");
        fields.put("encoding", "base64");

        assertStatusReturned(fields, 404, SKIP_MULTIPART);
    }

    /**
     * Test that when the cryptotoken is offline the status code is 503.
     */
    @Test
    public void test04HttpStatus503() {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "BTfUgfc6dXM0MoBS2jr5YmztlwKOILhJ9hFcIs12UZc=");
        fields.put("dataGroup3", "idxq5/Bqn0a1Za8D6rDs4L9gJNNlm346HQNXPP6wtZ0=");
        fields.put("encoding", "base64");

        try {
            // Deactivate crypto token
            try {
                getWorkerSession().deactivateSigner(new WorkerIdentifier(getSignerIdDummy1()));
            } catch (CryptoTokenOfflineException | InvalidWorkerIdException ex) {
                fail(ex.getMessage());
            }

            assertStatusReturned(fields, 503, SKIP_MULTIPART);
        } finally {
            // Activate crypto token
            try {
                getWorkerSession().activateSigner(new WorkerIdentifier(getSignerIdDummy1()), "foo123");
            } catch (CryptoTokenAuthenticationFailureException | CryptoTokenOfflineException | InvalidWorkerIdException ex) {
                fail(ex.getMessage());
            }
        }
    }

    /**
     * Test that when an exception occurs status code 500 is returned.
     */
    @Test
    public void test05HttpStatus500_exception() throws Exception {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "BTfUgfc6dXM0MoBS2jr5YmztlwKOILhJ9hFcIs12UZc=");
        fields.put("dataGroup3", "idxq5/Bqn0a1Za8D6rDs4L9gJNNlm346HQNXPP6wtZ0=");
        fields.put("encoding", "base64");

        // Set any bad properties that will make the signer fail with an exception
        final String originalSignatureAlgorithm = getWorkerSession().getCurrentWorkerConfig(
                getSignerIdDummy1()).getProperty("SIGNATUREALGORITHM");

        final String badKeyData = "_any-non-existing-alg_";
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), "SIGNATUREALGORITHM",
                badKeyData);
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        getWorkerSession().activateSigner(new WorkerIdentifier(getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);

        try {
            assertStatusReturned(fields, 500, SKIP_MULTIPART);
        } finally {
            // Restore
            if (originalSignatureAlgorithm == null) {
                getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "SIGNATUREALGORITHM");
            } else {
                getWorkerSession().setWorkerProperty(getSignerIdDummy1(), "SIGNATUREALGORITHM",
                    originalSignatureAlgorithm);
            }
            getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        }
    }

    private Properties parseMetadataResponse(final byte[] resp)
            throws IOException {
        final String propsString = new String(resp);
        final Properties props = new Properties();

        props.load(new StringReader(propsString));

        return props;
}

    /**
     * Test setting a single metadata param using REQUEST_METADATA.x.
     */
    @Test
    public void test06RequestMetadataSingleParam() throws Exception {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", "123");
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "BTfUgfc6dXM0MoBS2jr5YmztlwKOILhJ9hFcIs12UZc=");
        fields.put("dataGroup3", "idxq5/Bqn0a1Za8D6rDs4L9gJNNlm346HQNXPP6wtZ0=");
        fields.put("encoding", "base64");
        fields.put("REQUEST_METADATA.FOO", "BAR");

        assertStatusReturned(fields, 200, SKIP_MULTIPART);

        final byte[] resp = sendAndReadyBody(fields);
        final Properties props = parseMetadataResponse(resp);

        assertEquals("Contains property", "BAR", props.getProperty("FOO"));
    }

    /**
     * Test setting metadata using properties file syntax.
     */
    @Test
    public void test07RequestMetadataPropertiesFile() throws Exception {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", "123");
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "BTfUgfc6dXM0MoBS2jr5YmztlwKOILhJ9hFcIs12UZc=");
        fields.put("dataGroup3", "idxq5/Bqn0a1Za8D6rDs4L9gJNNlm346HQNXPP6wtZ0=");
        fields.put("encoding", "base64");
        fields.put("REQUEST_METADATA", "FOO=BAR\nFOO2=BAR2");

        assertStatusReturned(fields, 200, SKIP_MULTIPART);

        final byte[] resp = sendAndReadyBody(fields);
        final Properties props = parseMetadataResponse(resp);

        assertEquals("Contains property", "BAR", props.getProperty("FOO"));
        assertEquals("Contains property", "BAR2", props.getProperty("FOO2"));
    }

    /**
     * Test setting request metadata using properties file syntax
     * with a single parameter overriding.
     */
    @Test
    public void test08RequestMetadataOverride() throws Exception {
        Map<String, String> fields = new HashMap<>();
        fields.put("workerId", "123");
        fields.put("dataGroup1", "PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=");
        fields.put("dataGroup2", "BTfUgfc6dXM0MoBS2jr5YmztlwKOILhJ9hFcIs12UZc=");
        fields.put("dataGroup3", "idxq5/Bqn0a1Za8D6rDs4L9gJNNlm346HQNXPP6wtZ0=");
        fields.put("encoding", "base64");
        fields.put("REQUEST_METADATA", "FOO=BAR\nFOO2=BAR2");
        fields.put("REQUEST_METADATA.FOO", "OVERRIDE");

        assertStatusReturned(fields, 200, SKIP_MULTIPART);

        final byte[] resp = sendAndReadyBody(fields);
        final Properties props = parseMetadataResponse(resp);

        assertEquals("Contains property", "OVERRIDE", props.getProperty("FOO"));
        assertEquals("Contains property", "BAR2", props.getProperty("FOO2"));
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
