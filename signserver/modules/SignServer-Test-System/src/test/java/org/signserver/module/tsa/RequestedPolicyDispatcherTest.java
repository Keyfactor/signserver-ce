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
package org.signserver.module.tsa;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Random;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.*;
import org.junit.After;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.*;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;
import org.junit.Before;
import org.junit.Test;
import org.signserver.ejb.interfaces.IWorkerSession;

/**
 * Tests for RequestedProfileDistpatcher.
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class RequestedPolicyDispatcherTest extends ModulesTestCase {

    /** Worker ID for test dispatcher. */
    private static final int DISPATCHER0 = 8910;
    private static final int DISPATCHER9 = 8909;
    
    /** Worker ID for test worker. */
    private static final int WORKER1 = 8911;

    /** Worker ID for test worker. */
    private static final int WORKER2 = 8912;

    /** Worker ID for test worker. */
    private static final int WORKER3 = 8913;

    private static final String WORKER1_PROFILE = "1.2.13.1";
    private static final String WORKER1_ALTERNATIVE_PROFILE = "1.2.13.9";
    private static final String WORKER2_PROFILE = "1.2.13.2";
    private static final String WORKER3_PROFILE = "1.2.13.3";
    private static final String UNSUPPORTED_PROFILE = "1.2.13.55";
    
    private Random random = new Random(4711);

    private final IWorkerSession workerSession = getWorkerSession();

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @After
    protected void tearDown() throws Exception {
        TestingSecurityManager.remove();
    }

    /**
     * Setup signers and dispatchers definied in ts-setup1.properties.
     */
    @Test
    public void test00SetupDatabase() throws Exception {
        setProperties(getClass().getResourceAsStream("ts-setup1.properties"));
        workerSession.reloadConfiguration(DISPATCHER0);
        workerSession.reloadConfiguration(DISPATCHER9);
        workerSession.reloadConfiguration(WORKER1);
        workerSession.reloadConfiguration(WORKER2);
        workerSession.reloadConfiguration(WORKER3);
    }

    /**
     * Some basic tests around generating timestamps.
     * @throws Exception in case of error
     */
    @Test
    public void test01BasicTimeStamp() throws Exception {
        assertSuccessfulTimestamp(WORKER1);
        assertSuccessfulTimestamp(WORKER2);
        assertSuccessfulTimestamp(WORKER3);
    }
    
    /**
     * Sets the DispatchedAuthorizer for the dispatchees.
     */
    private void setDispatchedAuthorizerForAllWorkers() {
        workerSession.setWorkerProperty(WORKER1, "AUTHTYPE", "org.signserver.server.DispatchedAuthorizer");
        workerSession.setWorkerProperty(WORKER1, "AUTHORIZEALLDISPATCHERS", "true");
        workerSession.setWorkerProperty(WORKER2, "AUTHTYPE", "org.signserver.server.DispatchedAuthorizer");
        workerSession.setWorkerProperty(WORKER2, "AUTHORIZEALLDISPATCHERS", "true");
        workerSession.setWorkerProperty(WORKER3, "AUTHTYPE", "org.signserver.server.DispatchedAuthorizer");
        workerSession.setWorkerProperty(WORKER3, "AUTHORIZEALLDISPATCHERS", "true");
        workerSession.reloadConfiguration(WORKER1);
        workerSession.reloadConfiguration(WORKER2);
        workerSession.reloadConfiguration(WORKER3);
    }
    
    /**
     * Resets authorization for the dispatchees to be able to call them directly.
     */
    private void resetDispatchedAuthorizerForAllWorkers() {
        workerSession.setWorkerProperty(WORKER1, "AUTHTYPE", "NOAUTH");
        workerSession.removeWorkerProperty(WORKER1, "AUTHORIZEALLDISPATCHERS");
        workerSession.setWorkerProperty(WORKER2, "AUTHTYPE", "NOAUTH");
        workerSession.removeWorkerProperty(WORKER2, "AUTHORIZEALLDISPATCHERS");
        workerSession.setWorkerProperty(WORKER3, "AUTHTYPE", "NOAUTH");
        workerSession.removeWorkerProperty(WORKER3, "AUTHORIZEALLDISPATCHERS");
        workerSession.reloadConfiguration(WORKER1);
        workerSession.reloadConfiguration(WORKER2);
        workerSession.reloadConfiguration(WORKER3);
    }
    
    /**
     * Tests that the signers only accepts requests with their profile.
     */
    @Test
    public void test02AcceptedProfiles() throws Exception {
        TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
        TimeStampRequest req;
        TimeStampResponse res;
        
        resetDispatchedAuthorizerForAllWorkers();
        
        // Test that worker1 accepts its profile but not the other
        gen.setReqPolicy(WORKER1_PROFILE);
        req = gen.generate(TSPAlgorithms.SHA1, new byte[20], createNounce());
        res = requestTimeStamp(WORKER1, req);
        assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
        assertEquals("right profile", WORKER1_PROFILE, res.getTimeStampToken().getTimeStampInfo().getPolicy().getId());
        assertValid(req, res);
        
        gen.setReqPolicy(WORKER2_PROFILE);
        req = gen.generate(TSPAlgorithms.SHA1, new byte[20], createNounce());
        res = requestTimeStamp(WORKER1, req);
        assertEquals("token rejection", PKIStatus.REJECTION, res.getStatus());
        assertEquals(new PKIFailureInfo(PKIFailureInfo.unacceptedPolicy), res.getFailInfo());
        assertValid(req, res);
        
        gen.setReqPolicy(WORKER3_PROFILE);
        req = gen.generate(TSPAlgorithms.SHA1, new byte[20], createNounce());
        res = requestTimeStamp(WORKER1, req);
        assertEquals("token rejection", PKIStatus.REJECTION, res.getStatus());
        assertEquals(new PKIFailureInfo(PKIFailureInfo.unacceptedPolicy), res.getFailInfo());
        assertValid(req, res);
        
        // Test that worker2 accepts its profile but not the other
        gen.setReqPolicy(WORKER2_PROFILE);
        req = gen.generate(TSPAlgorithms.SHA1, new byte[20], createNounce());
        res = requestTimeStamp(WORKER2, req);
        assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
        assertEquals("right profile", WORKER2_PROFILE, res.getTimeStampToken().getTimeStampInfo().getPolicy().getId());
        assertValid(req, res);
        
        gen.setReqPolicy(WORKER1_PROFILE);
        req = gen.generate(TSPAlgorithms.SHA1, new byte[20], createNounce());
        res = requestTimeStamp(WORKER2, req);
        assertEquals("token rejection", PKIStatus.REJECTION, res.getStatus());
        assertEquals(new PKIFailureInfo(PKIFailureInfo.unacceptedPolicy), res.getFailInfo());
        
        gen.setReqPolicy(WORKER3_PROFILE);
        req = gen.generate(TSPAlgorithms.SHA1, new byte[20], createNounce());
        res = requestTimeStamp(WORKER2, req);
        assertEquals("token rejection", PKIStatus.REJECTION, res.getStatus());
        assertEquals(new PKIFailureInfo(PKIFailureInfo.unacceptedPolicy), res.getFailInfo());
        
        // Test that worker3 accepts its profile but not the other
        gen.setReqPolicy(WORKER3_PROFILE);
        req = gen.generate(TSPAlgorithms.SHA1, new byte[20], createNounce());
        res = requestTimeStamp(WORKER3, req);
        assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
        assertEquals("right profile", WORKER3_PROFILE, res.getTimeStampToken().getTimeStampInfo().getPolicy().getId());
        assertValid(req, res);
        
        gen.setReqPolicy(WORKER1_PROFILE);
        req = gen.generate(TSPAlgorithms.SHA1, new byte[20], createNounce());
        res = requestTimeStamp(WORKER3, req);
        assertEquals("token rejection", PKIStatus.REJECTION, res.getStatus());
        assertEquals(new PKIFailureInfo(PKIFailureInfo.unacceptedPolicy), res.getFailInfo());
        
        gen.setReqPolicy(WORKER2_PROFILE);
        req = gen.generate(TSPAlgorithms.SHA1, new byte[20], createNounce());
        res = requestTimeStamp(WORKER3, req);
        assertEquals("token rejection", PKIStatus.REJECTION, res.getStatus());
        assertEquals(new PKIFailureInfo(PKIFailureInfo.unacceptedPolicy), res.getFailInfo());
    }
    
    /**
     * Tests that requests going through the dispatcher gets the right profiles.
     */
    @Test
    public void test03AcceptedProfilesThroughDispatcher() throws Exception {
        try {
            TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
            TimeStampRequest req;
            TimeStampResponse res;
            
            setDispatchedAuthorizerForAllWorkers();
            
            // Test that a request with WORKER1_PROFILE is accepted
            gen.setReqPolicy(WORKER1_PROFILE);
            req = gen.generate(TSPAlgorithms.SHA256, new byte[32], createNounce());
            res = requestTimeStamp(DISPATCHER0, req);
            assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
            assertEquals("right profile", WORKER1_PROFILE, res.getTimeStampToken().getTimeStampInfo().getPolicy().getId());
            assertValid(req, res);
            
            // Test that a request with WORKER2_PROFILE is accepted
            gen.setReqPolicy(WORKER2_PROFILE);
            req = gen.generate(TSPAlgorithms.SHA256, new byte[32], createNounce());
            res = requestTimeStamp(DISPATCHER0, req);
            assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
            assertEquals("right profile", WORKER2_PROFILE, res.getTimeStampToken().getTimeStampInfo().getPolicy().getId());
            assertValid(req, res);
            
            // Test that a request with WORKER3_PROFILE is accepted
            gen.setReqPolicy(WORKER3_PROFILE);
            req = gen.generate(TSPAlgorithms.SHA256, new byte[32], createNounce());
            res = requestTimeStamp(DISPATCHER0, req);
            assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
            assertEquals("right profile", WORKER3_PROFILE, res.getTimeStampToken().getTimeStampInfo().getPolicy().getId());
            assertValid(req, res);
            
            // Test that an unknown profile is not accepted (USEDEFAULTIFMISMATCH=false)
            gen.setReqPolicy(UNSUPPORTED_PROFILE);
            req = gen.generate(TSPAlgorithms.SHA256, new byte[32], createNounce());
            res = requestTimeStamp(DISPATCHER0, req);
            assertEquals("token rejection", PKIStatus.REJECTION, res.getStatus());
            assertEquals(new PKIFailureInfo(PKIFailureInfo.unacceptedPolicy), res.getFailInfo());
            
            // Test that an unknown profile is not accepted (USEDEFAULTIFMISMATCH=true but profile not known by the default worker)
            gen.setReqPolicy(UNSUPPORTED_PROFILE);
            req = gen.generate(TSPAlgorithms.SHA256, new byte[32], createNounce());
            res = requestTimeStamp(DISPATCHER9, req);
            assertEquals("token rejection", PKIStatus.REJECTION, res.getStatus());
            assertEquals(new PKIFailureInfo(PKIFailureInfo.unacceptedPolicy), res.getFailInfo());
        } finally {
            resetDispatchedAuthorizerForAllWorkers();
        }
     }
     
    /**
     * Tests that requests which does not request a certain profile gets dispatched 
     * to the default worker.
     */
    @Test
    public void test04DefaultWorker() throws Exception {
        try {
            TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
            TimeStampRequest req;
            TimeStampResponse res;
        
            setDispatchedAuthorizerForAllWorkers();
        
            // Test that a request with no reqPolicy goes to WORKER1_PROFILE
            req = gen.generate(TSPAlgorithms.SHA256, new byte[32], createNounce());
            res = requestTimeStamp(DISPATCHER0, req);
            assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
            assertEquals("right profile", WORKER1_PROFILE, res.getTimeStampToken().getTimeStampInfo().getPolicy().getId());
            assertValid(req, res);
        } finally {
            resetDispatchedAuthorizerForAllWorkers();
        }
    }
    
    /**
     * Tests the USEDEFAULTIFMISMATCH option which dispatches requests to the 
     * default worker if no mapping matched.
     */
    @Test
    public void test05UseDefaultIfMisMatch() throws Exception {
        try {
            TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
            TimeStampRequest req;
            TimeStampResponse res;
            
            setDispatchedAuthorizerForAllWorkers();
            
            // Test that an profile not known by DISPATCHER0 but by a TSUnit1 is not accepted (USEDEFAULTIFMISMATCH=false)
            gen.setReqPolicy(WORKER1_ALTERNATIVE_PROFILE);
            req = gen.generate(TSPAlgorithms.SHA256, new byte[32], createNounce());
            res = requestTimeStamp(DISPATCHER0, req);
            assertEquals("token rejection", PKIStatus.REJECTION, res.getStatus());
            assertEquals(new PKIFailureInfo(PKIFailureInfo.unacceptedPolicy), res.getFailInfo());
            
            // Test that an profile not known by DISPATCHER9 but by a TSUnit1 is accepted (USEDEFAULTIFMISMATCH=true)
            gen.setReqPolicy(WORKER1_ALTERNATIVE_PROFILE);
            req = gen.generate(TSPAlgorithms.SHA256, new byte[32], createNounce());
            res = requestTimeStamp(DISPATCHER9, req);
            assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
            assertEquals("right profile", WORKER1_ALTERNATIVE_PROFILE, res.getTimeStampToken().getTimeStampInfo().getPolicy().getId());
            
            // Test that an profile not known by DISPATCHER9 and not by a TSUnit1 is rejected even though USEDEFAULTIFMISMATCH=true
            gen.setReqPolicy(UNSUPPORTED_PROFILE);
            req = gen.generate(TSPAlgorithms.SHA256, new byte[32], createNounce());
            res = requestTimeStamp(DISPATCHER9, req);
            assertEquals("token rejection", PKIStatus.REJECTION, res.getStatus());
            assertEquals(new PKIFailureInfo(PKIFailureInfo.unacceptedPolicy), res.getFailInfo());
        } finally {
            resetDispatchedAuthorizerForAllWorkers();
        }
    }
    
    /**
     * Test that the status string is included by default when mismatched policy
     * and no default worker is configured for mismatched policy.
     * @throws Exception
     */
    @Test
    public void test06IncludeStatusStringFailure() throws Exception {
        try {
            TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
            TimeStampRequest req;
            TimeStampResponse res;
            
            setDispatchedAuthorizerForAllWorkers();
            
            workerSession.setWorkerProperty(DISPATCHER0, TimeStampSigner.INCLUDESTATUSSTRING, "TRUE");
            
            // Test that an profile not known by DISPATCHER0 but by a TSUnit1 is not accepted (USEDEFAULTIFMISMATCH=false)
            gen.setReqPolicy(WORKER1_ALTERNATIVE_PROFILE);
            req = gen.generate(TSPAlgorithms.SHA256, new byte[32], createNounce());
            res = requestTimeStamp(DISPATCHER0, req);
            assertEquals("request contains unknown policy.", res.getStatusString());
        } finally {
            resetDispatchedAuthorizerForAllWorkers();
        }
    }
    
    /**
     * Test that the status string is not included when setting the INCLUDESTATUSSTRING to "FALSE"
     * on the dispatcher and no default worker is configured for mismatched policy.
     * @throws Exception
     */
    @Test
    public void test07ExcludeStatusStringFailure() throws Exception {
        try {
            TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
            TimeStampRequest req;
            TimeStampResponse res;
            
            setDispatchedAuthorizerForAllWorkers();
            
            workerSession.setWorkerProperty(DISPATCHER0, TimeStampSigner.INCLUDESTATUSSTRING, "FALSE");
            workerSession.reloadConfiguration(DISPATCHER0);
            
            // Test that an profile not known by DISPATCHER0 but by a TSUnit1 is not accepted (USEDEFAULTIFMISMATCH=false)
            gen.setReqPolicy(WORKER1_ALTERNATIVE_PROFILE);
            req = gen.generate(TSPAlgorithms.SHA256, new byte[32], createNounce());
            res = requestTimeStamp(DISPATCHER0, req);
            assertNull(res.getStatusString());
        } finally {
            resetDispatchedAuthorizerForAllWorkers();
        }
    }
    
    /**
     * Test that trying to send a request directly to a signer using the DispatchedAuthorizer fails.
     * @throws Exception
     */
    @Test
    public void test08DispatchedAuthorizerNonDispatched() throws Exception {
        try {
            setDispatchedAuthorizerForAllWorkers();
            
            TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
            TimeStampRequest req;
           
            req = gen.generate(TSPAlgorithms.SHA1, new byte[20], createNounce());
            requestTimeStamp(WORKER1, req);
            fail("Should not allow direct requests to a signer using a DispatchedAuthorizer");
        } catch (IllegalRequestException e) {
            // expected
        } catch (Exception e) {
            fail("Unexepected exception: " + e.getClass() + ": " + e.getMessage());
        } finally {
            resetDispatchedAuthorizerForAllWorkers();
        }
    }
    
    /**
     * Clean up.
     */
    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(DISPATCHER0);
        removeWorker(DISPATCHER9);
        removeWorker(WORKER1);
        removeWorker(WORKER2);
        removeWorker(WORKER3);
    }
    
    private void assertValid(TimeStampRequest req, TimeStampResponse res) {
        try {
            res.validate(req);
        } catch (TSPException ex) {
            fail(ex.getMessage());
        }
    }

    private void assertSuccessfulTimestamp(int worker) throws Exception {
        final int reqid = random.nextInt();
        final BigInteger nounce = createNounce();

        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], nounce);
        byte[] requestBytes = timeStampRequest.getEncoded();

        GenericSignRequest signRequest = new GenericSignRequest(reqid, requestBytes);

        final GenericSignResponse res = (GenericSignResponse) workerSession.process(worker, signRequest, new RequestContext());

        assertEquals("Request ID", reqid, res.getRequestID());

        Certificate signercert = res.getSignerCertificate();
        assertNotNull("contains certificate", signercert);

        final TimeStampResponse timeStampResponse = new TimeStampResponse((byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        assertEquals("Token granted", PKIStatus.GRANTED, timeStampResponse.getStatus());
        assertNotNull("Got timestamp token", timeStampResponse.getTimeStampToken());
    }
    
    private TimeStampResponse requestTimeStamp(int worker, TimeStampRequest request) throws IOException, IllegalRequestException, CryptoTokenOfflineException, TSPException, SignServerException {
        final int reqid = random.nextInt();
        byte[] requestBytes = request.getEncoded();

        GenericSignRequest signRequest = new GenericSignRequest(reqid, requestBytes);
        final GenericSignResponse res = (GenericSignResponse) workerSession.process(worker, signRequest, new RequestContext());
        return new TimeStampResponse((byte[]) res.getProcessedData());
    }
    
    private BigInteger createNounce() {
        byte[] bytes = new byte[8];
        random.nextBytes(bytes);
        return new BigInteger(bytes);
    }

}
