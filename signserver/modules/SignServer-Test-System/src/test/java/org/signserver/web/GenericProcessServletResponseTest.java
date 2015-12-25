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

import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;

import org.junit.Test;
import org.signserver.common.WorkerIdentifier;
import org.signserver.server.signers.EchoRequestMetadataSigner;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests that the right HTTP status codes are returned in different situations.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class GenericProcessServletResponseTest extends WebTestCase {

    private static final String KEYDATA = "KEYDATA";
    
    @Override
    protected String getServletURL() {
        return getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver/process";
    }

    /**
     * Sets up a dummy signer.
     * @throws Exception in case of error
     */
    @Test
    public void test00SetupDatabase() throws Exception {
        addDummySigner1(false);
        addCMSSigner1();
        addXMLValidator();
        addSigner(EchoRequestMetadataSigner.class.getName(), 123, "DummySigner123", true);
        getWorkerSession().activateSigner(new WorkerIdentifier(getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);
        getWorkerSession().activateSigner(new WorkerIdentifier(getSignerIdCMSSigner1()), ModulesTestCase.KEYSTORE_PASSWORD);
    }



    /**
     * Test that when an exception occurs status code 500 is returned.
     */
    @Test
    public void test05HttpStatus500_exception() throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException, InvalidWorkerIdException {
        Map<String, String> fields = new HashMap<String, String>();
        fields.put("workerName", getSignerNameDummy1());
        fields.put("data", "<root/>");

        // Set any bad properties that will make the signer fail with an exception
        final String originalSignatureAlgorithm = getWorkerSession().getCurrentWorkerConfig(
                getSignerIdDummy1()).getProperty("SIGNATUREALGORITHM");
        
        final String badKeyData = "_any-non-existing-alg_";
        getWorkerSession().setWorkerProperty(getSignerIdDummy1(), "SIGNATUREALGORITHM",
                badKeyData);
        getWorkerSession().reloadConfiguration(getSignerIdDummy1());
        getWorkerSession().activateSigner(new WorkerIdentifier(getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);

        try {
            assertStatusReturned(fields, 500);
        } finally {
            // Restore
            if (originalSignatureAlgorithm == null) {
                getWorkerSession().removeWorkerProperty(getSignerIdDummy1(), "SIGNATUREALGORITHM");
            } else {
                getWorkerSession().setWorkerProperty(getSignerIdDummy1(), "SIGNATUREALGORITHM",
                    originalSignatureAlgorithm);
            }
            getWorkerSession().reloadConfiguration(getSignerIdDummy1());
            getWorkerSession().activateSigner(new WorkerIdentifier(getSignerIdDummy1()), ModulesTestCase.KEYSTORE_PASSWORD);
        }
    }

    

    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
        removeWorker(getSignerIdCMSSigner1());
        removeWorker(getWorkerIdXmlValidator());
        removeWorker(getWorkerIdValidationService());
        removeWorker(123);
    }
}
