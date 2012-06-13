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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Random;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.ejbca.util.Base64;
import org.signserver.common.*;
import org.signserver.statusrepo.IStatusRepositorySession;
import org.signserver.statusrepo.common.StatusName;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Tests for the TimeStampSigner.
 *
 * @version $Id$
 */
public class TimeStampSignerTest extends ModulesTestCase {

    /** Logger for class. */
    private static final Logger LOG = Logger.getLogger(
            TimeStampSignerTest.class);

    /** The status repository session. */
    private static IStatusRepositorySession.IRemote repository;

    /** Worker ID for test worker. */
    private static final int WORKER1 = 8901;

    /** Worker ID for test worker. */
    private static final int WORKER2 = 8902;

    /** Worker ID for test worker. */
    private static final int WORKER3 = 8903;

    /** Worker ID for test worker. */
    private static final int WORKER4 = 8904;

    /** BASE64-encoded cert for WORKER1 */
    private static String CERTSTRING = "MIIEkTCCAnmgAwIBAgIIeCvAS5OwAJswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzEyMTU1NVoXDTIxMDUyNDEyMTU1NVowSjEUMBIGA1UEAwwLVFMgU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT38GG8i/bGnuFMwnOdg+caHMkdPBacRdBaIggwMPfE50SOZ2TLrDEHJotxYda7HS0+tX5dIcalmEYCls/ptHzO5TQpqdRTuTqxp5cMA379yhD0OqTVNAmHrvPj9IytktoAtB/xcjwkRTHagaCmg5SWNcLKyVUct7nbeRA5yDSJQsCAEGHNZbJ50vATg1DQEyKT87GKfSBsclA0WIIIHMt8/SRhpsUZxESayU6YA4KCxVtexF5x+COLB6CzzlRG9JA8WpX9yKgIMsMDAscsJLiLPjhET5hwAFm5ZRfQQG9LI06QNTGqukuTlDbYrQGAUR5ZXW00WNHfgS00CjUCu0QIDAQABo3gwdjAdBgNVHQ4EFgQUOF0FflO2G+IN6c92pCNlPoorGVwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADELkeIO9aiKjS/GaBUUhMr+k5UbVeK69WapU+7gTsWwa9D2vAOhAkfQ1OcUJoZaminv8pcNfo1Ey5qLtxBCmUy1fVomVWOPl6u1w8B6uYgE608hi2bfx28uIeksqpdqUX0Qf6ReUyl+FOh4xNrsyaF81TrIKt8ekq0iD+YAtT/jqgv4bUvs5fgIms4QOXgMUzNAP7cPU44KxcmR5I5Uy/Ag82hGIz64hZmeIDT0X59kbQvlZqFaiZvYOikoZSFvdM5kSVfItMgp7qmyLxuM/WaXqJWp6Mm+8ZZmcECugd4AEpE7xIiB7M/KEe+X4ItBNTKdAoaxWa+yeuYS7ol9rHt+Nogelj/06ZRQ0x03UqC7uKpgYAICjQEXIjcZofWSTh9KzKNfS1sQyIQ6yNTT2VMdYW9JC2OLKPV4AEJuBw30X8HOciJRRXOq9KRrIA2RSiaC5/3oAYscWuo31Fmj8CWQknXAIb39gPuZRwGOJbi1tUu2zmRsUNJfAe3hnvk+uxhnyp2vKB2KN5/VQgisx+8doEK/+Nbj/PPG/zASKimWG++5m0JNY4chIfR43gDDcF+4INof/8V84wbvUF+TpvP/mYM8wC9OkUyRvzqv9vjWOncCdbdjCuqPxDItwm9hhr+PbxsMaBes9rAiV9YT1FnpA++YpCufveFCQPDbCTgJ";

    
    /**
     * Base64 encoded request with policy 1.2.3.5.
     * <pre>
     * Version: 1
     *  Hash Algorithm: sha1
     *  Message data:
     *      0000 - 32 a0 61 7a ab 4c 9f e7-25 f1 b5 bc 44 12 91 18
     *      0010 - 0a d2 5b 73
     *  Policy OID: 1.2.3.5
     *  Nonce: unspecified
     *  Certificate required: no
     *  Extensions:
     *  </pre>
     */
    private static final String REQUEST_WITH_POLICY1235 =
            "MCsCAQEwITAJBgUrDgMCGgUABBQyoGF6q0yf5yXxtbxEEpEYCtJbcwYDKgMF";

    private static String signserverhome;
    private static int moduleVersion;

    private Random random = new Random(4711);


    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();

        repository = ServiceLocator.getInstance().lookupRemote(
                IStatusRepositorySession.IRemote.class);
    }

    /* (non-Javadoc)
     * @see junit.framework.TestCase#tearDown()
     */
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
    }

    public void test00SetupDatabase() throws Exception {
        setProperties(new File(getSignServerHome(), "modules/SignServer-Module-TSA/src/conf/junittest-part-config.properties"));
        workerSession.reloadConfiguration(WORKER1);
        workerSession.reloadConfiguration(WORKER2);
        workerSession.reloadConfiguration(WORKER3);
        workerSession.reloadConfiguration(WORKER4);
    }

    public void test01BasicTimeStamp() throws Exception {
        assertSuccessfulTimestamp(WORKER1);
    }

    private void assertSuccessfulTimestamp(int worker) throws Exception {
        int reqid = random.nextInt();

        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();

        GenericSignRequest signRequest =
                new GenericSignRequest(reqid, requestBytes);


        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                worker, signRequest, new RequestContext());

        assertTrue(reqid == res.getRequestID());

        Certificate signercert = res.getSignerCertificate();

        assertNotNull(signercert);

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        assertEquals("Token granted", PKIStatus.GRANTED,
                timeStampResponse.getStatus());
        assertNotNull("Got timestamp token",
                timeStampResponse.getTimeStampToken());
    }

    /*
     * Test method for 'org.signserver.server.MRTDSigner.getStatus()'.
     */
    public void test02GetStatus() throws Exception {

        SignerStatus stat = (SignerStatus) workerSession.getStatus(8901);
        assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);
    }

    /**
     * Test that a timestamp token is not granted for an policy not listed in
     * ACCEPTEDPOLICIES and that a proper resoonse is sent back.
     * @throws Exception in case of exception
     */
    public void test03NotAcceptedPolicy() throws Exception {
        // WORKER2 has ACCEPTEDPOLICIES=1.2.3
        // Create an request with another policy (1.2.3.5 != 1.2.3)
        final TimeStampRequest timeStampRequest = new TimeStampRequest(
                Base64.decode(REQUEST_WITH_POLICY1235.getBytes()));
        
        final byte[] requestBytes = timeStampRequest.getEncoded();

        final GenericSignRequest signRequest = new GenericSignRequest(13,
                requestBytes);

        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                WORKER2, signRequest, new RequestContext());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
            (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        LOG.info("Response: " + timeStampResponse.getStatusString());

        assertEquals("Token rejected", PKIStatus.REJECTION,
                timeStampResponse.getStatus());
    }

    /**
     * Tests that the timestamp signer returnes a time stamp response with
     * the timeNotAvailable status if the Date is null.
     * @throws Exception in case of exception
     */
    public void test04timeNotAvailable() throws Exception {
        assertTimeNotAvailable(WORKER3);
    }

    /**
     * Tests that the timestamp is only granted when the INSYNC property
     * is set.
     * @throws Exception in case of exception
     */
    public void test05ReadingStatusTimeSource() throws Exception {
        
        // Test with insync
        repository.update(StatusName.TIMESOURCE0_INSYNC.name(), "true");
        assertSuccessfulTimestamp(WORKER4);

        // Test without insync
        repository.update(StatusName.TIMESOURCE0_INSYNC.name(), "");
        assertTimeNotAvailable(WORKER4);
    }
    

    /**
     * Utility method to return the hash length for the hash types we're testing against
     * 
     * @param hashType
     * @return
     */
    private int getHashLength(String hashType) {
    	if (TSPAlgorithms.SHA256.equals(hashType)) {
    		return 32;
    	} else if (TSPAlgorithms.SHA512.equals(hashType)) {
    		return 64;
    	} else if (TSPAlgorithms.RIPEMD160.equals(hashType)) {
    		return 20;
    	} else {
    		LOG.error("Trying to use an unknow hash algorithm, bailing out...");
    		return -1;
    	}
    }
    
    private void testWithHash(final String hashAlgo) throws Exception {
    	int reqid = random.nextInt();
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
    	final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
    			hashAlgo, new byte[getHashLength(hashAlgo)], BigInteger.valueOf(100));
    	
        byte[] requestBytes = timeStampRequest.getEncoded();

        GenericSignRequest signRequest =
                new GenericSignRequest(reqid, requestBytes);


        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                WORKER1, signRequest, new RequestContext());

        TimeStampResponse timeStampResponse = null;
        try {
        	// check response
        	timeStampResponse = new TimeStampResponse((byte[]) res.getProcessedData());
        	timeStampResponse.validate(timeStampRequest);
        	LOG.info("Response: " + timeStampResponse.getStatusString());
        } catch (TSPException e) {
        	fail("Failed to verify response");
        } catch (IOException e) {
        	fail("Failed to verify response");
        }
        
        
        final TimeStampToken token = timeStampResponse.getTimeStampToken();
        
        try {
        	final CertificateFactory factory = CertificateFactory.getInstance("X.509");
        	final X509Certificate cert =
        		(X509Certificate) factory.generateCertificate(new ByteArrayInputStream(Base64.decode(CERTSTRING.getBytes())));
        	token.validate(cert, "BC");
        } catch (TSPException e) {
        	fail("Failed to validate response token");
        }
    }
    
    /**
     * Tests requesting a timetamp with SHA256 as the hash algorithm
     * verify the hash and signature algortithms of the respons token
     * 
     * @throws Exception
     */
    public void test06HashSHA256() throws Exception {
    	testWithHash(TSPAlgorithms.SHA256);
    }
    
    /**
     * Test requesting a timestamp with SHA512 as the hash algorithm
     * 
     * @param worker
     * @throws Exception
     */
    public void test07HashSHA512() throws Exception {
    	testWithHash(TSPAlgorithms.SHA512);
    }
    
    /**
     * Test requesting a timestamp with RIPEMD160 as the hash algorithm
     * 
     * @param worker
     * @throws Exception
     */
    public void test08HashRIPE160() throws Exception {
    	testWithHash(TSPAlgorithms.RIPEMD160);
    }
        
    private void assertTimeNotAvailable(int worker) throws Exception {
        final int reqid = random.nextInt();

        final TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(114));
        final byte[] requestBytes = timeStampRequest.getEncoded();

        final GenericSignRequest signRequest =
                new GenericSignRequest(reqid, requestBytes);


        final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                worker, signRequest, new RequestContext());

        assertTrue(reqid == res.getRequestID());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(
                (byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        LOG.info("Response: " + timeStampResponse.getStatusString());

        assertEquals("Token not granted", PKIStatus.REJECTION,
                timeStampResponse.getStatus());

        assertEquals("PKIFailureInfo.timeNotAvailable",
                new PKIFailureInfo(PKIFailureInfo.timeNotAvailable),
                timeStampResponse.getFailInfo());

        assertNull("No timestamp token",
                timeStampResponse.getTimeStampToken());
    }

    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKER1);
        removeWorker(WORKER2);
        removeWorker(WORKER3);
    }

}
