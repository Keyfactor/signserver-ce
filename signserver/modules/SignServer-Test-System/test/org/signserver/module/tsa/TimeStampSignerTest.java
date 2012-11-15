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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.*;
import org.ejbca.util.Base64;
import org.signserver.common.*;
import org.signserver.statusrepo.IStatusRepositorySession;
import org.signserver.statusrepo.common.StatusName;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
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
    
    /** Worker ID for test worker. */
    private static final int WORKER20 = 8920;

    /** BASE64-encoded cert for WORKER1 */
    private static String CERTSTRING = "MIIEkTCCAnmgAwIBAgIIeCvAS5OwAJswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMDUyNzEyMTU1NVoXDTIxMDUyNDEyMTU1NVowSjEUMBIGA1UEAwwLVFMgU2lnbmVyIDExEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnT38GG8i/bGnuFMwnOdg+caHMkdPBacRdBaIggwMPfE50SOZ2TLrDEHJotxYda7HS0+tX5dIcalmEYCls/ptHzO5TQpqdRTuTqxp5cMA379yhD0OqTVNAmHrvPj9IytktoAtB/xcjwkRTHagaCmg5SWNcLKyVUct7nbeRA5yDSJQsCAEGHNZbJ50vATg1DQEyKT87GKfSBsclA0WIIIHMt8/SRhpsUZxESayU6YA4KCxVtexF5x+COLB6CzzlRG9JA8WpX9yKgIMsMDAscsJLiLPjhET5hwAFm5ZRfQQG9LI06QNTGqukuTlDbYrQGAUR5ZXW00WNHfgS00CjUCu0QIDAQABo3gwdjAdBgNVHQ4EFgQUOF0FflO2G+IN6c92pCNlPoorGVwwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQgeiHe6K27Aqj7cVikCWK52FgFojAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBADELkeIO9aiKjS/GaBUUhMr+k5UbVeK69WapU+7gTsWwa9D2vAOhAkfQ1OcUJoZaminv8pcNfo1Ey5qLtxBCmUy1fVomVWOPl6u1w8B6uYgE608hi2bfx28uIeksqpdqUX0Qf6ReUyl+FOh4xNrsyaF81TrIKt8ekq0iD+YAtT/jqgv4bUvs5fgIms4QOXgMUzNAP7cPU44KxcmR5I5Uy/Ag82hGIz64hZmeIDT0X59kbQvlZqFaiZvYOikoZSFvdM5kSVfItMgp7qmyLxuM/WaXqJWp6Mm+8ZZmcECugd4AEpE7xIiB7M/KEe+X4ItBNTKdAoaxWa+yeuYS7ol9rHt+Nogelj/06ZRQ0x03UqC7uKpgYAICjQEXIjcZofWSTh9KzKNfS1sQyIQ6yNTT2VMdYW9JC2OLKPV4AEJuBw30X8HOciJRRXOq9KRrIA2RSiaC5/3oAYscWuo31Fmj8CWQknXAIb39gPuZRwGOJbi1tUu2zmRsUNJfAe3hnvk+uxhnyp2vKB2KN5/VQgisx+8doEK/+Nbj/PPG/zASKimWG++5m0JNY4chIfR43gDDcF+4INof/8V84wbvUF+TpvP/mYM8wC9OkUyRvzqv9vjWOncCdbdjCuqPxDItwm9hhr+PbxsMaBes9rAiV9YT1FnpA++YpCufveFCQPDbCTgJ";

    /** Dummy OID used for testing an invalid hashing algorithm */
    private static String DUMMY_OID = "1.42.42.42.42";
    
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
        // Test signing
        final TimeStampResponse response = assertSuccessfulTimestamp(WORKER1);

        // Test that it is using the right algorithm
        final TimeStampToken token = response.getTimeStampToken();
        final SignerInformation si = (SignerInformation) token.toCMSSignedData().getSignerInfos().getSigners().iterator().next();
        assertEquals("sha1withrsa", "1.2.840.113549.1.1.1", si.getEncryptionAlgOID());
    }

    private TimeStampResponse assertSuccessfulTimestamp(int worker) throws Exception {
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
        
        // Validate the signature of the token
        try {
            final SignerInformationVerifier infoVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build((X509Certificate) signercert);
            timeStampResponse.getTimeStampToken().validate(infoVerifier);
        } catch (TSPValidationException ex) {
            LOG.error("Token validation failed", ex);
            fail("Token validation failed: " + ex.getMessage());
        }
        
        return timeStampResponse;
    }

    /**
     * Tests the status returned by the worker.
     */
    public void test02GetStatus() throws Exception {
        SignerStatus stat = (SignerStatus) workerSession.getStatus(8901);
        assertEquals("token status", SignerStatus.STATUS_ACTIVE, stat.getTokenStatus());
        assertEquals("ALLOK: " + stat.getFatalErrors(), 0, stat.getFatalErrors().size());
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
    private int getHashLength(ASN1ObjectIdentifier hashType) {
    	if (TSPAlgorithms.SHA1.equals(hashType)) {
    		return 20;
    	} else if (TSPAlgorithms.SHA256.equals(hashType)) {
    		return 32;
    	} else if (TSPAlgorithms.SHA512.equals(hashType)) {
    		return 64;
    	} else if (TSPAlgorithms.RIPEMD160.equals(hashType)) {
    		return 20;
    	} else {
    		LOG.info("Trying to use an unknow hash algorithm, using dummy length");
    		// return the length of a SHA1 hash as a dummy value to allow passing
    		// invalid hash algo names for testing
    		return 20;
    	}
    }
    
    private int testWithHash(final ASN1ObjectIdentifier hashAlgo) throws Exception {
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
      	
        	if (timeStampResponse.getStatus() != PKIStatus.GRANTED) {
        		// return early and don't attempt to get a token
        		return timeStampResponse.getStatus();
        	}
        	
        	// check the hash value from the response
        	TimeStampToken token = timeStampResponse.getTimeStampToken();
        	AlgorithmIdentifier algo = token.getTimeStampInfo().getHashAlgorithm();
        	assertEquals("Timestamp response is using incorrect hash algorithm", hashAlgo, algo.getAlgorithm()); 	
        	
        	Collection signerInfos = token.toCMSSignedData().getSignerInfos().getSigners();
        	
        	// there should be one SignerInfo
        	assertEquals("There should only be one signer in the timestamp response", 1, signerInfos.size());
        	
        	for (Object o : signerInfos) {
        		SignerInformation si = (SignerInformation) o;
        		
        		// test the response signature algorithm
        		assertEquals("Timestamp used unexpected signature algorithm", TSPAlgorithms.SHA1.toString(), si.getDigestAlgOID());
        		assertEquals("Timestamp is signed with unexpected signature encryption algorithm", "1.2.840.113549.1.1.1", si.getEncryptionAlgOID());
        	}

        	
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
       
        return timeStampResponse.getStatus();
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
    
    
    /**
     * Test requesting a timestamp with a hash algorithm not included in the accepted
     * algorithms list
     * 
     * @param worker
     * @throws Exception
     */
    public void test09HashWithNotAllowedAlgorithm() throws Exception {
    	// set accepted algorithms to SHA1
    	workerSession.setWorkerProperty(WORKER1, TimeStampSigner.ACCEPTEDALGORITHMS, "SHA1");
    	workerSession.reloadConfiguration(WORKER1);
    	
    	int status = testWithHash(TSPAlgorithms.SHA256);
    	assertEquals("Should return status REJECTION", PKIStatus.REJECTION, status);
    }    
    
    /**
     * Test request a timestamp using a made-up dummy hash algorithm name
     * 
     * @param worker
     * @throws Exception
     */
    public void test10HashWithIllegalAlgorithm() throws Exception {
    	// reset accepted algorithms
    	workerSession.removeWorkerProperty(WORKER1, TimeStampSigner.ACCEPTEDALGORITHMS);
    	workerSession.reloadConfiguration(WORKER1);
    	
    	ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(DUMMY_OID);
    	int status = testWithHash(oid);

    	assertEquals("Should not accept an invalid hash algorithm", PKIStatus.REJECTION, status);
    }

    /**
     * Test setting ACCEPTEDALGORITHMS and sign using that hash algorithm
     * 
     * @param worker
     * @throws Exception
     */
    public void test11HashWithAllowedAlgorithm() throws Exception {
    	// set accepted algorithms to SHA1
    	workerSession.setWorkerProperty(WORKER1, TimeStampSigner.ACCEPTEDALGORITHMS, "SHA1");
    	workerSession.reloadConfiguration(WORKER1);
    	
    	int status = testWithHash(TSPAlgorithms.SHA1);
    	assertEquals("Should return status GRANTED", PKIStatus.GRANTED, status);
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

    /**
     * Check that we either include the signer certificate if it is missing or
     * otherwise fails the request.
     * 
     * In addition Health check should also report an error for this.
     * 
     * RFC#3161 2.4.1:
     * "If the certReq field is present and set to true, the TSA's public key
     *  certificate that is referenced by the ESSCertID identifier inside a
     *  SigningCertificate attribute in the response MUST be provided by the
     *  TSA in the certificates field from the SignedData structure in that
     *  response.  That field may also contain other certificates."
     */
    public void test09SignerCertificateMustBeIncluded() throws Exception {
        List<Certificate> chain = workerSession.getSignerCertificateChain(WORKER2);
        final X509Certificate subject = (X509Certificate) chain.get(0);
        X509Certificate issuer = (X509Certificate) chain.get(1);
        
        // Now, don't include the signer certificate in the chain
        // For some reason we need to upload the signer certificate again :S
        workerSession.uploadSignerCertificate(WORKER2, subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(WORKER2, Arrays.asList(issuer.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(WORKER2);
        
        if (!subject.equals(workerSession.getSignerCertificate(WORKER2))) {
            LOG.info("Subject: " + subject);
            LOG.info("Signer: " + workerSession.getSignerCertificate(WORKER2));
            throw new Exception("Something is fishy. Test assumed the signer certificate to be present");
        }
        // Test the status of the worker
        WorkerStatus actualStatus = workerSession.getStatus(WORKER2);
        assertEquals("should be error as signer certificate is not included in chain", 1, actualStatus.getFatalErrors().size());
        assertTrue("error should talk about missing signer certificate: " + actualStatus.getFatalErrors(), actualStatus.getFatalErrors().get(0).contains("ertificate"));
        
        // Send a request including certificates
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        timeStampRequestGenerator.setCertReq(true);
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest =
                new GenericSignRequest(123124, requestBytes);
        try {
            final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                    WORKER2, signRequest, new RequestContext());

            final TimeStampResponse timeStampResponse = new TimeStampResponse((byte[]) res.getProcessedData());
            timeStampResponse.validate(timeStampRequest);

            if (PKIStatus.GRANTED == timeStampResponse.getStatus()) {
                fail("Should have failed as the signer is miss-configured");
            }
        } catch (CryptoTokenOfflineException ex) {
            assertTrue("message should talk about missing signer certificate", ex.getMessage().contains("igner certificate"));
        } finally {
            // Restore
            workerSession.uploadSignerCertificate(WORKER2, subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2, asListOfByteArrays(chain), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2);
        }
    }
    
    /**
     * Tests that status is not OK and that an failure is generated when trying
     * to sign when the right signer certificate is not configured.
     *
     */
    public void test10WrongSignerCertificate() throws Exception {
        final List<Certificate> chain = workerSession.getSignerCertificateChain(WORKER2);
        final X509Certificate subject = (X509Certificate) workerSession.getSignerCertificate(WORKER2);
        
        // Any other certificate that will no match the key-pair
        final X509Certificate other = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=Other").addExtension(new CertExt(org.bouncycastle.asn1.x509.X509Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))).build());
        
        try {
            // Use the other certificate which will not match the key + the right cert in chain        
            workerSession.uploadSignerCertificate(WORKER2, other.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2, Arrays.asList(subject.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2);

            // Test the status of the worker
            WorkerStatus actualStatus = workerSession.getStatus(WORKER2);
            assertEquals("should be error as the right signer certificate is not configured", 2, actualStatus.getFatalErrors().size());
            assertTrue("error should talk about incorrect signer certificate: " + actualStatus.getFatalErrors(), actualStatus.getFatalErrors().get(0).contains("ertificate"));

            // Send a request including certificates
            TimeStampRequestGenerator timeStampRequestGenerator =
                    new TimeStampRequestGenerator();
            timeStampRequestGenerator.setCertReq(true);
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                    TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
            byte[] requestBytes = timeStampRequest.getEncoded();
            GenericSignRequest signRequest =
                    new GenericSignRequest(123124, requestBytes);
            try {
                final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                        WORKER2, signRequest, new RequestContext());

                final TimeStampResponse timeStampResponse = new TimeStampResponse((byte[]) res.getProcessedData());
                timeStampResponse.validate(timeStampRequest);

                if (PKIStatus.GRANTED == timeStampResponse.getStatus()) {
                    fail("Should have failed as the signer is miss-configured");
                }
            } catch (CryptoTokenOfflineException ex) {
                assertTrue("message should talk about incorrect signer certificate", ex.getMessage().contains("igner certificate"));
            }
        } finally {
            // Restore
            workerSession.uploadSignerCertificate(WORKER2, subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2, asListOfByteArrays(chain), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2);
        }
    }
    
    /**
     * Tests that status is not OK and that an failure is generated when trying
     * to sign when the right signer certificate is not configured in the 
     * certificate chain property.
     *
     */
    public void test10WrongSignerCertificate_InChain() throws Exception {
        final List<Certificate> chain = workerSession.getSignerCertificateChain(WORKER2);
        final X509Certificate subject = (X509Certificate) workerSession.getSignerCertificate(WORKER2);
        
        // Any other certificate that will no match the key-pair
        final X509Certificate other = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=Other").build());
        
        try {
            // Use the right certificate but the other in the certificate chain
            workerSession.uploadSignerCertificate(WORKER2, subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2, Arrays.asList(other.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2);

            // Test the status of the worker
            WorkerStatus actualStatus = workerSession.getStatus(WORKER2);
            assertEquals("should be error as the right signer certificate is not configured", 1, actualStatus.getFatalErrors().size());
            assertTrue("error should talk about incorrect signer certificate: " + actualStatus.getFatalErrors(), actualStatus.getFatalErrors().get(0).contains("ertificate"));

            // Send a request including certificates
            TimeStampRequestGenerator timeStampRequestGenerator =
                    new TimeStampRequestGenerator();
            timeStampRequestGenerator.setCertReq(true);
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                    TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
            byte[] requestBytes = timeStampRequest.getEncoded();
            GenericSignRequest signRequest =
                    new GenericSignRequest(123124, requestBytes);
            try {
                final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                        WORKER2, signRequest, new RequestContext());

                final TimeStampResponse timeStampResponse = new TimeStampResponse((byte[]) res.getProcessedData());
                timeStampResponse.validate(timeStampRequest);

                if (PKIStatus.GRANTED == timeStampResponse.getStatus()) {
                    fail("Should have failed as the signer is miss-configured");
                }
            } catch (CryptoTokenOfflineException ex) {
                assertTrue("message should talk about incorrect signer certificate", ex.getMessage().contains("igner certificate"));
            }
        } finally {
            // Restore
            workerSession.uploadSignerCertificate(WORKER2, subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2, asListOfByteArrays(chain), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2);
        }
    }
    
    private Collection<byte[]> asListOfByteArrays(List<Certificate> chain) throws CertificateEncodingException {
        ArrayList results = new ArrayList(chain.size());
        for (Certificate c : chain) {
            results.add(c.getEncoded());
        }
        return results;
    }

    /**
     * Tests that if REQUIREVALIDCHAIN=true is specified only the signer certificate
     * and its issuer (and its issuer and so on...) is allowed in the chain.
     * Also tests that the default is to not do this check.
     */
    public void test11RequireValidChain() throws Exception {
    
        // First make sure we don't have this property set
        workerSession.removeWorkerProperty(WORKER1, "REQUIREVALIDCHAIN");
        
        // Setup an invalid chain
        final List<Certificate> chain = workerSession.getSignerCertificateChain(WORKER1);
        final X509Certificate subject = (X509Certificate) workerSession.getSignerCertificate(WORKER1);
        
        // Any other certificate that will no match the key-pair
        final X509Certificate other = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=Other cert").build());
        
        try {
            // An not strictly valid chain as it contains an additional certificate at the end
            // (In same use cases this might be okey but now we are testing the 
            //  strict checking with the REQUIREVALIDCHAIN property set)
            List<Certificate> ourChain = new LinkedList<Certificate>();
            ourChain.addAll(chain);
            ourChain.add(other);
            workerSession.uploadSignerCertificate(WORKER1, subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER1, asListOfByteArrays(ourChain), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER1);
            
            // Test the status of the worker: should be ok as we aren't doing strict checking
            WorkerStatus actualStatus = workerSession.getStatus(WORKER1);
            assertEquals("should be okey as aren't doing strict checking", 0, actualStatus.getFatalErrors().size());
            // Test signing: should also be ok
            assertTokenGranted(WORKER1);
            
            // Now change to strict checking
            workerSession.setWorkerProperty(WORKER1, "REQUIREVALIDCHAIN", "true");
            workerSession.reloadConfiguration(WORKER1);
            
            // Test the status of the worker: should be offline as we don't have a valid chain
            actualStatus = workerSession.getStatus(WORKER1);
            assertEquals("should be offline as we don't have a valid chain", 1, actualStatus.getFatalErrors().size());
            // Test signing: should give error
            assertTokenNotGranted(WORKER1);
            
        } finally {
            // Restore
            workerSession.uploadSignerCertificate(WORKER1, subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER1, asListOfByteArrays(chain), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER1);
        }
        
    }
    
    /**
     * Tests that status is not OK and that an failure is generated when trying
     * to sign when the right signer certificate is not configured.
     *
     */
    public void test12WrongEkuInSignerCertificate() throws Exception {
        
        final List<Certificate> chain = workerSession.getSignerCertificateChain(WORKER2);
        final X509Certificate subject = (X509Certificate) workerSession.getSignerCertificate(WORKER2);
        
        // Certifiate without id_kp_timeStamping
        final X509Certificate certNoEku = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=Without EKU").setSubjectPublicKey(subject.getPublicKey()).build());
        
        // Certificate with non-critical id_kp_timeStamping
        boolean critical = false;
        final X509Certificate certEku = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=With non-critical EKU").setSubjectPublicKey(subject.getPublicKey()).addExtension(new CertExt(X509Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))).build());
        
        // OK: Certificate with critical id_kp_timeStamping
        critical = true;
        final X509Certificate certCritEku = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=With critical EKU").setSubjectPublicKey(subject.getPublicKey()).addExtension(new CertExt(X509Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))).build());
        
        try {
            // Fail: No id_kp_timeStamping
            workerSession.uploadSignerCertificate(WORKER2, certNoEku.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2, Arrays.asList(certNoEku.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2);
            WorkerStatus actualStatus = workerSession.getStatus(WORKER2);
            List<String> errors = actualStatus.getFatalErrors();
            String errorsString = errors.toString();
            // should be error as the signer certificate is missing id_kp_timeStamping and EKU is not critical
            LOG.info("errorsString: " + errorsString);
            assertEquals(2, errors.size());
            assertTrue("error should talk about missing extended key usage timeStamping: " + errorsString, errorsString.contains("timeStamping")); // Will need adjustment if language changes
            assertTrue("error should talk about missing critical extension: " + errorsString, errorsString.contains("critical")); // Will need adjustment if language changes
            
            // Ok: Certificate with critical id_kp_timeStamping
            workerSession.uploadSignerCertificate(WORKER2, certCritEku.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2, Arrays.asList(certCritEku.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2);
            actualStatus = workerSession.getStatus(WORKER2);
            assertEquals(0, actualStatus.getFatalErrors().size());
            
            // Fail: No non-critical id_kp_timeStamping
            workerSession.uploadSignerCertificate(WORKER2, certEku.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2, Arrays.asList(certEku.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2);
            actualStatus = workerSession.getStatus(WORKER2);
            errorsString = errors.toString();
            // should be error as the signer certificate is missing id_kp_timeStamping
            assertEquals(1, actualStatus.getFatalErrors().size());
            // error should talk about missing critical EKU
            assertTrue("errorString: " + errorsString, errorsString.contains("critical"));  // Will need adjustment if language changes
        } finally {
            // Restore
            workerSession.uploadSignerCertificate(WORKER2, subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2, asListOfByteArrays(chain), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2);
        }
    }
    
    /** Tests issuance of time-stamp token when an EC key is specified. */
    public void test20BasicTimeStampECDSA() throws Exception {
        final int workerId = WORKER20;
        try {
            // Setup signer
            final File keystore = new File(getSignServerHome(), "res/test/dss10/dss10_signer5ec.p12");
            if (!keystore.exists()) {
                throw new FileNotFoundException(keystore.getAbsolutePath());
            }
            addP12DummySigner(TimeStampSigner.class.getName(), workerId, "TestTimeStampP12ECDSA", keystore, "foo123");
            workerSession.setWorkerProperty(workerId, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(workerId, "SIGNATUREALGORITHM", "SHA1WithECDSA");
            workerSession.reloadConfiguration(workerId);
            
            // Test signing
            TimeStampResponse response = assertSuccessfulTimestamp(WORKER20);
            
        } finally {
            removeWorker(workerId);
        }
    }
    
    private void assertTokenGranted(int workerId) throws Exception {
        TimeStampRequestGenerator timeStampRequestGenerator =
                    new TimeStampRequestGenerator();
        timeStampRequestGenerator.setCertReq(true);
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest =
                new GenericSignRequest(123124, requestBytes);
        try {
            final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                    workerId, signRequest, new RequestContext());

            final TimeStampResponse timeStampResponse = new TimeStampResponse((byte[]) res.getProcessedData());
            timeStampResponse.validate(timeStampRequest);

            assertEquals(PKIStatus.GRANTED, timeStampResponse.getStatus());
        } catch (CryptoTokenOfflineException ex) {
            fail(ex.getMessage());
        }
    }
    
    private void assertTokenNotGranted(int workerId) throws Exception {
        TimeStampRequestGenerator timeStampRequestGenerator =
                    new TimeStampRequestGenerator();
        timeStampRequestGenerator.setCertReq(true);
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest =
                new GenericSignRequest(123124, requestBytes);
        try {
            final GenericSignResponse res = (GenericSignResponse) workerSession.process(
                    workerId, signRequest, new RequestContext());

            final TimeStampResponse timeStampResponse = new TimeStampResponse((byte[]) res.getProcessedData());
            timeStampResponse.validate(timeStampRequest);

            assertFalse(PKIStatus.GRANTED == timeStampResponse.getStatus());
        } catch (CryptoTokenOfflineException ignored) { //NOPMD
            // OK
        }
    }

    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKER1);
        removeWorker(WORKER2);
        removeWorker(WORKER3);
        removeWorker(WORKER4);
    }

}
