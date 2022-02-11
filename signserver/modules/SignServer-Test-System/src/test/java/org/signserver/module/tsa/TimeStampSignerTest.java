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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.*;
import org.bouncycastle.util.encoders.Base64;
import org.junit.After;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.*;
import org.signserver.statusrepo.common.StatusName;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestUtils;

import org.junit.Before;
import org.junit.Test;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.statusrepo.StatusRepositorySessionRemote;

/**
 * Tests for the TimeStampSigner.
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TimeStampSignerTest extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(
            TimeStampSignerTest.class);

    /** The status repository session. */
    private static StatusRepositorySessionRemote repository;

    /** Worker ID for test worker. */
    private static final WorkerIdentifier WORKER1 = new WorkerIdentifier(8901);

    /** Worker ID for test worker. */
    private static final WorkerIdentifier WORKER2 = new WorkerIdentifier(8902);

    /** Worker ID for test worker. */
    private static final WorkerIdentifier WORKER3 = new WorkerIdentifier(8903);

    /** Worker ID for test worker. */
    private static final WorkerIdentifier WORKER4 = new WorkerIdentifier(8904);

    /** Worker ID for test worker. */
    private static final WorkerIdentifier WORKER5 = new WorkerIdentifier(8905);

    /** Worker ID for test worker. */
    private static final WorkerIdentifier WORKER20 = new WorkerIdentifier(8920);

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
    private static final String SHA256WITHRSA_ENCRYPTION_ALG_OID ="1.2.840.113549.1.1.11";

    private final Random RANDOM = new Random(4711);

    private final WorkerSession workerSession = getWorkerSession();
    private final ProcessSessionRemote processSession = getProcessSession();

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        repository = ServiceLocator.getInstance().lookupRemote(StatusRepositorySessionRemote.class);
    }

    @After
    public void tearDown() {
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        LOG.info("test00SetupDatabase");
        addTimeStampSigner(WORKER1.getId(), "TestTSA1", true);
        workerSession.setWorkerProperty(WORKER1.getId(), "ACCEPTANYPOLICY", "true");

        addTimeStampSigner(WORKER2.getId(), "TestTSA2", true);
        workerSession.setWorkerProperty(WORKER2.getId(), "ACCEPTANYPOLICY", "false");
        workerSession.setWorkerProperty(WORKER2.getId(), "ACCEPTEDPOLICIES", "1.2.3");
        workerSession.reloadConfiguration(WORKER2.getId());

        addTimeStampSigner(WORKER3.getId(), "TestTSA3", true);
        workerSession.setWorkerProperty(WORKER3.getId(), "ACCEPTANYPOLICY", "true");
        workerSession.setWorkerProperty(WORKER3.getId(), "TIMESOURCE", "org.signserver.server.NullTimeSource");
        workerSession.reloadConfiguration(WORKER3.getId());

        addTimeStampSigner(WORKER4.getId(), "TestTSA4", true);
        workerSession.setWorkerProperty(WORKER4.getId(), "ACCEPTANYPOLICY", "true");
        workerSession.setWorkerProperty(WORKER4.getId(), "TIMESOURCE", "org.signserver.server.StatusReadingLocalComputerTimeSource");
        workerSession.reloadConfiguration(WORKER4.getId());

        // Worker with a Null timesource, using legacy encoding
        addTimeStampSigner(WORKER5.getId(), "TestTSA5", true);
        workerSession.setWorkerProperty(WORKER5.getId(), "ACCEPTANYPOLICY", "true");
        workerSession.setWorkerProperty(WORKER5.getId(), "TIMESOURCE", "org.signserver.server.NullTimeSource");
        workerSession.setWorkerProperty(WORKER5.getId(), "LEGACYENCODING", "true");
        workerSession.reloadConfiguration(WORKER5.getId());
    }

    @Test
    public void test01BasicTimeStamp() throws Exception {
        LOG.info("test01BasicTimeStamp");
        // Test signing
        final TimeStampResponse response = assertSuccessfulTimestamp(WORKER1, true);

        // Test that it is using the right algorithm
        final TimeStampToken token = response.getTimeStampToken();
        final SignerInformation si = token.toCMSSignedData().getSignerInfos().getSigners().iterator().next();
        assertEquals("sha256withrsa", SHA256WITHRSA_ENCRYPTION_ALG_OID, si.getEncryptionAlgOID()); // SHA256withRSA is default signature algorithm
    }

    /**
     * Test successfully doing a TSA request.
     *
     * @param worker Worker ID
     * @param includeSigningTime If the signingTime signed CMS attribute is expected or not
     * @return Time stamp response
     */
    private TimeStampResponse assertSuccessfulTimestamp(WorkerIdentifier worker,
            final boolean includeSigningTime) throws Exception {
        int reqid = RANDOM.nextInt();

        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();

        GenericSignRequest signRequest =
                new GenericSignRequest(reqid, requestBytes);


        final GenericSignResponse res = (GenericSignResponse) processSession.process(
                worker, signRequest, new RemoteRequestContext());

        assertEquals(reqid, res.getRequestID());

        Certificate signercert = res.getSignerCertificate();

        assertNotNull(signercert);

        final TimeStampResponse timeStampResponse = new TimeStampResponse(res.getProcessedData());
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

        // check the signingTime signed attribute
        final AttributeTable attrs = timeStampResponse.getTimeStampToken().getSignedAttributes();
        final Attribute attr = attrs.get(CMSAttributes.signingTime);

        if (includeSigningTime) {
            assertNotNull("Should contain signingTime signed attribute", attr);
        } else {
            assertNull("Should not contain signingTime signed attribute", attr);
        }

        return timeStampResponse;
    }

    /**
     * Return raw data of a TSA request's response.
     *
     * @param worker worker identifier
     * @return processed data as byte[]
     */
    private byte[] getResponseData(WorkerIdentifier worker) throws Exception {
        int reqid = RANDOM.nextInt();

        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();

        GenericSignRequest signRequest =
                new GenericSignRequest(reqid, requestBytes);


        final GenericSignResponse res = (GenericSignResponse) processSession.process(
                worker, signRequest, new RemoteRequestContext());

        return res.getProcessedData();
    }

    /**
     * Tests the status returned by the worker.
     */
    @Test
    public void test02GetStatus() throws Exception {
        LOG.info("test02GetStatus");
        StaticWorkerStatus stat = (StaticWorkerStatus) workerSession.getStatus(new WorkerIdentifier(8901));
        assertEquals("token status", WorkerStatus.STATUS_ACTIVE, stat.getTokenStatus());
        assertEquals("ALLOK: " + stat.getFatalErrors(), 0, stat.getFatalErrors().size());
    }

    /**
     * Test that a timestamp token is not granted for a policy not listed in
     * ACCEPTEDPOLICIES and that a proper response is sent back.
     * @throws Exception in case of exception
     */
    @Test
    public void test03NotAcceptedPolicy() throws Exception {
        LOG.info("test03NotAcceptedPolicy");
        // WORKER2 has ACCEPTEDPOLICIES=1.2.3
        // Create an request with another policy (1.2.3.5 != 1.2.3)
        final TimeStampRequest timeStampRequest = new TimeStampRequest(
                Base64.decode(REQUEST_WITH_POLICY1235.getBytes()));

        final byte[] requestBytes = timeStampRequest.getEncoded();

        final GenericSignRequest signRequest = new GenericSignRequest(13,
                requestBytes);

        final GenericSignResponse res = (GenericSignResponse) processSession.process(
                WORKER2, signRequest, new RemoteRequestContext());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(res.getProcessedData());
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
    @Test
    public void test04timeNotAvailable() throws Exception {
        LOG.info("test04timeNotAvailable");
        assertTimeNotAvailable(WORKER3);
    }

    /**
     * Tests that the timestamp signer returnes a time stamp response with
     * the timeNotAvailable status if the Date is null and legacy encoding
     * is used.
     * @throws Exception in case of exception
     */
    @Test
    public void test04timeNotAvailableLegacyEncoding() throws Exception {
        LOG.info("test04timeNotAvailableLegacyEncoding");
        assertTimeNotAvailable(WORKER5);
    }

    /**
     * Tests that the timestamp is only granted when the INSYNC property
     * is set.
     * @throws Exception in case of exception
     */
    @Test
    public void test05ReadingStatusTimeSource() throws Exception {
        LOG.info("test05ReadingStatusTimeSource");
        // Test with insync
        repository.update(StatusName.TIMESOURCE0_INSYNC.name(), "true");
        assertSuccessfulTimestamp(WORKER4, true);

        // Test without insync
        repository.update(StatusName.TIMESOURCE0_INSYNC.name(), "");
        assertTimeNotAvailable(WORKER4);
    }

    /**
     * Utility method to return the hash length for the hash types we're testing against
     *
     * @param hashType ASN1 Object Identifier
     * @return hash length
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
    		LOG.info("Trying to use an unknown hash algorithm, using dummy length");
    		// return the length of a SHA1 hash as a dummy value to allow passing
    		// invalid hash algo names for testing
    		return 20;
    	}
    }

    /**
     * Helper method testing with given request hash algorithm and (optionally
     * a given certificate digest algorithm.
     *
     * @param hashAlgo ASN1 Object Identifier
     * @return certificate digest
     */
    private int testWithHash(final ASN1ObjectIdentifier hashAlgo,
                             final String certDigestAlgo,
                             final boolean expectESSCertIDv2) throws Exception {
    	int reqid = RANDOM.nextInt();
        TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
    	final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
    			hashAlgo, new byte[getHashLength(hashAlgo)], BigInteger.valueOf(100));

        byte[] requestBytes = timeStampRequest.getEncoded();

        GenericSignRequest signRequest =
                new GenericSignRequest(reqid, requestBytes);

        try {
            if (certDigestAlgo != null) {
                workerSession.setWorkerProperty(WORKER1.getId(),
                                                "CERTIFICATE_DIGEST_ALGORITHM",
                                                certDigestAlgo);
                workerSession.reloadConfiguration(WORKER1.getId());
            }

            final GenericSignResponse res = (GenericSignResponse) processSession.process(
                    WORKER1, signRequest, new RemoteRequestContext());

            final X509Certificate cert = (X509Certificate) workerSession.getSignerCertificate(WORKER1);

            TimeStampResponse timeStampResponse = null;
            try {
                    // check response
                    timeStampResponse = new TimeStampResponse(res.getProcessedData());
                    timeStampResponse.validate(timeStampRequest);

                    if (timeStampResponse.getStatus() != PKIStatus.GRANTED) {
                            // return early and don't attempt to get a token
                            return timeStampResponse.getStatus();
                    }

                    // check the hash value from the response
                    TimeStampToken token = timeStampResponse.getTimeStampToken();
                    AlgorithmIdentifier algo = token.getTimeStampInfo().getHashAlgorithm();
                    assertEquals("Timestamp response is using incorrect hash algorithm", hashAlgo, algo.getAlgorithm());

                    Collection<SignerInformation> signerInfos = token.toCMSSignedData().getSignerInfos().getSigners();

                    // there should be one SignerInfo
                    assertEquals("There should only be one signer in the timestamp response", 1, signerInfos.size());

                    for (SignerInformation si : signerInfos) {

                        // test the response signature algorithm
                        // SHA256withRSA is default signature algorithm and same will be used for verification
                        assertEquals("Timestamp used unexpected signature algorithm", TSPAlgorithms.SHA256.toString(), si.getDigestAlgOID());
                        assertEquals("Timestamp is signed with unexpected signature encryption algorithm", SHA256WITHRSA_ENCRYPTION_ALG_OID, si.getEncryptionAlgOID());

                                final AttributeTable attrs = si.getSignedAttributes();
                                final ASN1EncodableVector scAttrs =
                                        attrs.getAll(expectESSCertIDv2 ?
                                                     PKCSObjectIdentifiers.id_aa_signingCertificateV2 :
                                                     PKCSObjectIdentifiers.id_aa_signingCertificate);

                                assertEquals("Should contain a signingCertificate signed attribute", 1, scAttrs.size());

                                final String digestAlg = getBCDigestAlg(certDigestAlgo);
                                TestUtils.checkSigningCertificateAttribute(
                                        Attribute.getInstance(scAttrs.get(0)), cert,
                                        digestAlg, expectESSCertIDv2);
                    }
            } catch (TSPException | IOException e) {
                    fail("Failed to verify response");
            }


            final TimeStampToken token = timeStampResponse.getTimeStampToken();

            try {
                    final SignerInformationVerifier infoVerifier =
                            new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert);

                    token.validate(infoVerifier);
            } catch (TSPException e) {
                    fail("Failed to validate response token");
            }

            return timeStampResponse.getStatus();
        } finally {
            workerSession.removeWorkerProperty(WORKER1.getId(),
                                               "CERTIFICATE_DIGEST_ALGORITHM");
            workerSession.reloadConfiguration(WORKER1.getId());
        }

    }

    private String getBCDigestAlg(final String alg) {
        if (alg == null) {
            return "SHA-256";
        }

        switch (alg) {
            case "SHA1":
            case "SHA-1":
                return "SHA-1";
            case "SHA224":
            case "SHA-224":
                return "SHA-224";
            case "SHA256":
            case "SHA-256":
                return "SHA-256";
            case "SHA384":
            case "SHA-384":
                return "SHA-384";
            case "SHA512":
            case "SHA-512":
                return "SHA-512";
            default:
                return null;
        }
    }

    /**
     * Tests requesting a timestamp with SHA256 as the hash algorithm
     * verify the hash and signature algorithms of the response token
     */
    @Test
    public void test06HashSHA256() throws Exception {
        LOG.info("test06HashSHA256");
    	testWithHash(TSPAlgorithms.SHA256, null, true);
    }

    /**
     * Test requesting a timestamp with SHA512 as the hash algorithm
     */
    @Test
    public void test07HashSHA512() throws Exception {
        LOG.info("test07HashSHA512");
    	testWithHash(TSPAlgorithms.SHA512, null, true);
    }

    /**
     * Test requesting a timestamp with RIPEMD160 as the hash algorithm
     */
    @Test
    public void test08HashRIPE160() throws Exception {
        LOG.info("test08HashRIPE160");
    	testWithHash(TSPAlgorithms.RIPEMD160, null, true);
    }


    /**
     * Test requesting a timestamp with a hash algorithm not included in the accepted
     * algorithms list
     */
    @Test
    public void test09HashWithNotAllowedAlgorithm() throws Exception {
        LOG.info("test09HashWithNotAllowedAlgorithm");
    	// set accepted algorithms to SHA1
    	workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.ACCEPTEDALGORITHMS, "SHA1");
    	workerSession.reloadConfiguration(WORKER1.getId());

    	int status = testWithHash(TSPAlgorithms.SHA256, null, true);
    	assertEquals("Should return status REJECTION", PKIStatus.REJECTION, status);
    }

    /**
     * Test request a timestamp using a made-up dummy hash algorithm name
     */
    @Test
    public void test10HashWithIllegalAlgorithm() throws Exception {
        LOG.info("test10HashWithIllegalAlgorithm");
    	// reset accepted algorithms
    	workerSession.removeWorkerProperty(WORKER1.getId(), TimeStampSigner.ACCEPTEDALGORITHMS);
    	workerSession.reloadConfiguration(WORKER1.getId());

        // Dummy OID used for testing an invalid hashing algorithm
        String DUMMY_OID = "1.42.42.42.42";
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(DUMMY_OID);
    	int status = testWithHash(oid, null, true);

    	assertEquals("Should not accept an invalid hash algorithm", PKIStatus.REJECTION, status);
    }

    /**
     * Test setting ACCEPTEDALGORITHMS and sign using that hash algorithm
     */
    @Test
    public void test11HashWithAllowedAlgorithm() throws Exception {
        LOG.info("test11HashWithAllowedAlgorithm");
    	// set accepted algorithms to SHA256
    	workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.ACCEPTEDALGORITHMS, "SHA256");
    	workerSession.reloadConfiguration(WORKER1.getId());

    	int status = testWithHash(TSPAlgorithms.SHA256, null, true);
    	assertEquals("Should return status GRANTED", PKIStatus.GRANTED, status);
    }

    private void assertTimeNotAvailable(WorkerIdentifier worker) throws Exception {
        final int reqid = RANDOM.nextInt();

        final TimeStampRequestGenerator timeStampRequestGenerator =
                new TimeStampRequestGenerator();
        final TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(114));
        final byte[] requestBytes = timeStampRequest.getEncoded();

        final GenericSignRequest signRequest =
                new GenericSignRequest(reqid, requestBytes);


        final GenericSignResponse res = (GenericSignResponse) processSession.process(
                worker, signRequest, new RemoteRequestContext());

        assertEquals(reqid, res.getRequestID());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(res.getProcessedData());
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
     * In addition, Health check should also report an error for this.
     *
     * RFC#3161 2.4.1:
     * "If the certReq field is present and set to true, the TSA's public key
     *  certificate that is referenced by the ESSCertID identifier inside a
     *  SigningCertificate attribute in the response MUST be provided by the
     *  TSA in the certificates field from the SignedData structure in that
     *  response.  That field may also contain other certificates."
     */
    @Test
    public void test09SignerCertificateMustBeIncluded() throws Exception {
        LOG.info("test09SignerCertificateMustBeIncluded");
        List<Certificate> chain = workerSession.getSignerCertificateChain(WORKER2);
        final X509Certificate subject = (X509Certificate) chain.get(0);
        X509Certificate issuer = (X509Certificate) chain.get(1);

        // Now, don't include the signer certificate in the chain
        // For some reason we need to upload the signer certificate again :S
        workerSession.uploadSignerCertificate(WORKER2.getId(), subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(WORKER2.getId(), Collections.singletonList(issuer.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(WORKER2.getId());

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
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest =
                new GenericSignRequest(123124, requestBytes);
        try {
            final GenericSignResponse res = (GenericSignResponse) processSession.process(
                    WORKER2, signRequest, new RemoteRequestContext());

            final TimeStampResponse timeStampResponse = new TimeStampResponse(res.getProcessedData());
            timeStampResponse.validate(timeStampRequest);

            if (PKIStatus.GRANTED == timeStampResponse.getStatus()) {
                fail("Should have failed as the signer is miss-configured");
            }
        } catch (CryptoTokenOfflineException ex) {
            assertTrue("message should talk about missing signer certificate", ex.getMessage().contains("igner certificate"));
        } finally {
            // Restore
            workerSession.uploadSignerCertificate(WORKER2.getId(), subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2.getId(), asListOfByteArrays(chain), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2.getId());
        }
    }

    /**
     * Tests that status is not OK and that an failure is generated when trying
     * to sign when the right signer certificate is not configured.
     *
     */
    @Test
    public void test10WrongSignerCertificate() throws Exception {
        LOG.info("test10WrongSignerCertificate");
        final List<Certificate> chain = workerSession.getSignerCertificateChain(WORKER2);
        final X509Certificate subject = (X509Certificate) workerSession.getSignerCertificate(WORKER2);

        // Any other certificate that will no match the key-pair
        final X509Certificate other = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=Other").addExtension(new CertExt(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))).build());

        try {
            // Use the other certificate which will not match the key + the right cert in chain
            workerSession.uploadSignerCertificate(WORKER2.getId(), other.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2.getId(), Collections.singletonList(subject.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2.getId());

            // Test the status of the worker
            WorkerStatus actualStatus = workerSession.getStatus(WORKER2);
            assertEquals("should be error as the right signer certificate is not configured", 2, actualStatus.getFatalErrors().size());
            assertTrue("error should talk about incorrect signer certificate: " + actualStatus.getFatalErrors(), actualStatus.getFatalErrors().get(0).contains("ertificate"));

            // Send a request including certificates
            TimeStampRequestGenerator timeStampRequestGenerator =
                    new TimeStampRequestGenerator();
            timeStampRequestGenerator.setCertReq(true);
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                    TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
            byte[] requestBytes = timeStampRequest.getEncoded();
            GenericSignRequest signRequest =
                    new GenericSignRequest(123124, requestBytes);
            try {
                final GenericSignResponse res = (GenericSignResponse) processSession.process(
                        WORKER2, signRequest, new RemoteRequestContext());

                final TimeStampResponse timeStampResponse = new TimeStampResponse(res.getProcessedData());
                timeStampResponse.validate(timeStampRequest);

                if (PKIStatus.GRANTED == timeStampResponse.getStatus()) {
                    fail("Should have failed as the signer is miss-configured");
                }
            } catch (CryptoTokenOfflineException ex) {
                assertTrue("message should talk about incorrect signer certificate", ex.getMessage().contains("igner certificate"));
            }
        } finally {
            // Restore
            workerSession.uploadSignerCertificate(WORKER2.getId(), subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2.getId(), asListOfByteArrays(chain), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2.getId());
        }
    }

    /**
     * Tests that signing fails when the right signer certificate is not
     * configured but works if VERIFY_TOKEN_SIGNATURE set to false.
     *
     */
    @Test
    public void test52WrongSignerCertificate_SigningFailed() throws Exception {
        LOG.info("test52WrongSignerCertificate_SigningFailed");
        final List<Certificate> chain = workerSession.getSignerCertificateChain(WORKER2);
        final X509Certificate subject = (X509Certificate) workerSession.getSignerCertificate(WORKER2);

        // Any other certificate that will not match the key-pair
        final X509Certificate other = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=Other").addExtension(new CertExt(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))).build());

        try {
            // Use the other certificate which will not match the key
            workerSession.uploadSignerCertificate(WORKER2.getId(), other.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2.getId(), Collections.singletonList(other.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2.getId());

            // Test the status of the worker
            WorkerStatus actualStatus = workerSession.getStatus(WORKER2);
            assertEquals("should be error as the right signer certificate is not configured", 1, actualStatus.getFatalErrors().size());
            assertTrue("error should talk about incorrect signer certificate: " + actualStatus.getFatalErrors(), actualStatus.getFatalErrors().get(0).contains("Certificate does not match key"));

            // Send a request
            try {
                assertTokenGranted(WORKER2);
            } catch (SignServerException ex) {
                assertTrue("message should talk about incorrect signer certificate", ex.getMessage().contains("Token validation failed"));
            }

            // Now change to - not verifying token signature and signing should work
            workerSession.setWorkerProperty(WORKER2.getId(), "VERIFY_TOKEN_SIGNATURE", "false");
            workerSession.reloadConfiguration(WORKER2.getId());
            assertTokenGranted(WORKER2);
        } finally {
            // Restore
            workerSession.setWorkerProperty(WORKER2.getId(), "VERIFY_TOKEN_SIGNATURE", "true");
            workerSession.uploadSignerCertificate(WORKER2.getId(), subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2.getId(), asListOfByteArrays(chain), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2.getId());
        }
    }

    /**
     * Tests that status is not OK and that an failure is generated when trying
     * to sign when the right signer certificate is not configured in the
     * certificate chain property.
     *
     */
    @Test
    public void test10WrongSignerCertificate_InChain() throws Exception {
        LOG.info("test10WrongSignerCertificate_InChain");
        final List<Certificate> chain = workerSession.getSignerCertificateChain(WORKER2);
        final X509Certificate subject = (X509Certificate) workerSession.getSignerCertificate(WORKER2);

        // Any other certificate that will no match the key-pair
        final X509Certificate other = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=Other").build());

        try {
            // Use the right certificate but the other in the certificate chain
            workerSession.uploadSignerCertificate(WORKER2.getId(), subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2.getId(), Collections.singletonList(other.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2.getId());

            // Test the status of the worker
            WorkerStatus actualStatus = workerSession.getStatus(WORKER2);
            assertEquals("should be error as the right signer certificate is not configured", 1, actualStatus.getFatalErrors().size());
            assertTrue("error should talk about incorrect signer certificate: " + actualStatus.getFatalErrors(), actualStatus.getFatalErrors().get(0).contains("ertificate"));

            // Send a request including certificates
            TimeStampRequestGenerator timeStampRequestGenerator =
                    new TimeStampRequestGenerator();
            timeStampRequestGenerator.setCertReq(true);
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                    TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
            byte[] requestBytes = timeStampRequest.getEncoded();
            GenericSignRequest signRequest =
                    new GenericSignRequest(123124, requestBytes);
            try {
                final GenericSignResponse res = (GenericSignResponse) processSession.process(
                        WORKER2, signRequest, new RemoteRequestContext());

                final TimeStampResponse timeStampResponse = new TimeStampResponse(res.getProcessedData());
                timeStampResponse.validate(timeStampRequest);

                if (PKIStatus.GRANTED == timeStampResponse.getStatus()) {
                    fail("Should have failed as the signer is miss-configured");
                }
            } catch (CryptoTokenOfflineException ex) {
                assertTrue("message should talk about incorrect signer certificate", ex.getMessage().contains("igner certificate"));
            }
        } finally {
            // Restore
            workerSession.uploadSignerCertificate(WORKER2.getId(), subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2.getId(), asListOfByteArrays(chain), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2.getId());
        }
    }

    private List<byte[]> asListOfByteArrays(List<Certificate> chain) throws CertificateEncodingException {
        List<byte[]> results = new ArrayList<>(chain.size());
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
    @Test
    public void test11RequireValidChain() throws Exception {
        LOG.info("test11RequireValidChain");
        // First make sure we don't have this property set
        workerSession.removeWorkerProperty(WORKER1.getId(), "REQUIREVALIDCHAIN");

        // Setup an invalid chain
        final List<Certificate> chain = workerSession.getSignerCertificateChain(WORKER1);
        final X509Certificate subject = (X509Certificate) workerSession.getSignerCertificate(WORKER1);

        // Any other certificate that will no match the key-pair
        final X509Certificate other = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=Other cert").build());

        try {
            // Not strictly valid chain as it contains an additional certificate at the end
            // (In same use cases this might be ok, but now we are testing the
            //  strict checking with the REQUIREVALIDCHAIN property set)
            List<Certificate> ourChain = new LinkedList<>(chain);
            ourChain.add(other);
            workerSession.uploadSignerCertificate(WORKER1.getId(), subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER1.getId(), asListOfByteArrays(ourChain), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER1.getId());

            // Test the status of the worker: should be ok as we aren't doing strict checking
            WorkerStatus actualStatus = workerSession.getStatus(WORKER1);
            assertEquals("should be okey as aren't doing strict checking", 0, actualStatus.getFatalErrors().size());
            // Test signing: should also be ok
            assertTokenGranted(WORKER1);

            // Now change to strict checking
            workerSession.setWorkerProperty(WORKER1.getId(), "REQUIREVALIDCHAIN", "true");
            workerSession.reloadConfiguration(WORKER1.getId());

            // Test the status of the worker: should be offline as we don't have a valid chain
            actualStatus = workerSession.getStatus(WORKER1);
            assertEquals("should be offline as we don't have a valid chain", 1, actualStatus.getFatalErrors().size());
            // Test signing: should give error
            assertTokenNotGranted(WORKER1);

        } finally {
            // Restore
            workerSession.uploadSignerCertificate(WORKER1.getId(), subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER1.getId(), asListOfByteArrays(chain), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER1.getId());
        }
    }

    /**
     * Tests that status is not OK and that an failure is generated when trying
     * to sign when the right signer certificate is not configured.
     *
     */
    @Test
    public void test12WrongEkuInSignerCertificate() throws Exception {
        LOG.info("test12WrongEkuInSignerCertificate");
        final List<Certificate> chain = workerSession.getSignerCertificateChain(WORKER2);
        final X509Certificate subject = (X509Certificate) workerSession.getSignerCertificate(WORKER2);

        // Certifiate without id_kp_timeStamping
        final X509Certificate certNoEku = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=Without EKU").setSubjectPublicKey(subject.getPublicKey()).build());

        // Certificate with non-critical id_kp_timeStamping
        boolean critical = false;
        final X509Certificate certEku = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=With non-critical EKU").setSubjectPublicKey(subject.getPublicKey()).addExtension(new CertExt(Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))).build());

        // OK: Certificate with critical id_kp_timeStamping
        critical = true;
        final X509Certificate certCritEku = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=With critical EKU").setSubjectPublicKey(subject.getPublicKey()).addExtension(new CertExt(Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping))).build());

        // Certificate with additional extended key usage, besides id_kp_timeStamping
        final X509Certificate certCritEkuAndAdditional =
                new JcaX509CertificateConverter().getCertificate(new CertBuilder().
                        setSubject("CN=With critical EKU").
                        setSubjectPublicKey(subject.getPublicKey()).
                        addExtension(new CertExt(Extension.extendedKeyUsage,
                            critical,
                            new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_timeStamping,
                                                                     KeyPurposeId.id_kp_emailProtection}
                        ))).
                        build());
        try {
            // Fail: No id_kp_timeStamping
            workerSession.uploadSignerCertificate(WORKER2.getId(), certNoEku.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2.getId(), Collections.singletonList(certNoEku.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2.getId());
            WorkerStatus actualStatus = workerSession.getStatus(WORKER2);
            List<String> errors = actualStatus.getFatalErrors();
            String errorsString = errors.toString();
            // should be error as the signer certificate is missing id_kp_timeStamping and EKU is not critical
            LOG.info("errorsString: " + errorsString);
            assertEquals(2, errors.size());
            assertTrue("error should talk about missing extended key usage timeStamping: " + errorsString, errorsString.contains("timeStamping")); // Will need adjustment if language changes
            assertTrue("error should talk about missing critical extension: " + errorsString, errorsString.contains("critical")); // Will need adjustment if language changes

            // Ok: Certificate with critical id_kp_timeStamping
            workerSession.uploadSignerCertificate(WORKER2.getId(), certCritEku.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2.getId(), Collections.singletonList(certCritEku.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2.getId());
            actualStatus = workerSession.getStatus(WORKER2);
            assertEquals(0, actualStatus.getFatalErrors().size());

            // Fail: No non-critical id_kp_timeStamping
            workerSession.uploadSignerCertificate(WORKER2.getId(), certEku.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2.getId(), Collections.singletonList(certEku.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2.getId());
            actualStatus = workerSession.getStatus(WORKER2);
            errorsString = errors.toString();
            // should be error as the signer certificate is missing id_kp_timeStamping
            assertEquals(1, actualStatus.getFatalErrors().size());
            // error should talk about missing critical EKU
            assertTrue("errorString: " + errorsString, errorsString.contains("critical"));  // Will need adjustment if language changes

            // Fail: Additional EKU
            workerSession.uploadSignerCertificate(WORKER2.getId(), certCritEkuAndAdditional.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2.getId(), Collections.singletonList(certCritEkuAndAdditional.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2.getId());
            actualStatus = workerSession.getStatus(WORKER2);
            // should be error as the signer certificate is missing id_kp_timeStamping
            assertEquals(1, actualStatus.getFatalErrors().size());
            errorsString = actualStatus.getFatalErrors().toString();
            // error should talk about missing critical EKU
            assertTrue("Should mention additional extended key usages: " + errorsString,
                    errorsString.contains("No other extended key usages than timeStamping is allowed"));  // Will need adjustment if language changes


        } finally {
            // Restore
            workerSession.uploadSignerCertificate(WORKER2.getId(), subject.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER2.getId(), asListOfByteArrays(chain), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER2.getId());
        }
    }

    /**
     * Tests that WorkerSession.getCertificateIssues() returns an issue for an incorrect certificate
     * and not for an OK one.
     */
    @Test
    public void test13WrongEkuWorkerSessionGetCertificateIssues() throws Exception {
        LOG.info("test13WrongEkuWorkerSessionGetCertificateIssues");
        final List<Certificate> chain = workerSession.getSignerCertificateChain(WORKER2);
        final X509Certificate subject = (X509Certificate) workerSession.getSignerCertificate(WORKER2);

        // Certifiate without id_kp_timeStamping
        final Certificate certNoEku = new JcaX509CertificateConverter().getCertificate(new CertBuilder().setSubject("CN=Without EKU").setSubjectPublicKey(subject.getPublicKey()).build());
        List<String> certificateIssues = workerSession.getCertificateIssues(WORKER2.getId(), Collections.singletonList(certNoEku));
        assertFalse("at least one issuse", certificateIssues.isEmpty());

        // Ok certificate should not give any issues
        certificateIssues = workerSession.getCertificateIssues(WORKER2.getId(), chain);
        assertTrue("should be okey", certificateIssues.isEmpty());
    }

    /** Tests issuance of time-stamp token when an EC key is specified. */
    @Test
    public void test20BasicTimeStampECDSA() throws Exception {
        LOG.info("test20BasicTimeStampECDSA");
        final int workerId = WORKER20.getId();
        try {
            // Setup signer
            final File keystore = new File(getSignServerHome(), "res/test/dss10/dss10_signer5ec.p12");
            if (!keystore.exists()) {
                throw new FileNotFoundException(keystore.getAbsolutePath());
            }
            addP12DummySigner(TimeStampSigner.class.getName(), workerId,
                    "TestTimeStampP12ECDSA", keystore, "foo123", "signerec");
            workerSession.setWorkerProperty(workerId, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(workerId, "ACCEPTANYPOLICY", "true");
            workerSession.setWorkerProperty(workerId, "SIGNATUREALGORITHM", "SHA1WithECDSA");
            workerSession.reloadConfiguration(workerId);

            // Test signing
            TimeStampResponse response = assertSuccessfulTimestamp(WORKER20, true);

            // Test that it is using the right algorithm
            TimeStampToken token = response.getTimeStampToken();
            SignerInformation si = token.toCMSSignedData().getSignerInfos().getSigners().iterator().next();
            assertEquals("sha1withecdsa", "1.2.840.10045.4.1", si.getEncryptionAlgOID());

            // Test with SHA256WithECDSA
            workerSession.setWorkerProperty(workerId, "SIGNATUREALGORITHM", "SHA256WithECDSA");
            workerSession.reloadConfiguration(workerId);

            // Test signing
            response = assertSuccessfulTimestamp(WORKER20, true);

            // Test that it is using the right algorithm
            token = response.getTimeStampToken();
            si = token.toCMSSignedData().getSignerInfos().getSigners().iterator().next();
            assertEquals("sha256withecdsa", "1.2.840.10045.4.3.2", si.getEncryptionAlgOID());

        } finally {
            removeWorker(workerId);
        }
    }

    /** Tests issuance of time-stamp token when an DSA key is specified. */
    @Test
    public void test21BasicTimeStampDSA() throws Exception {
        LOG.info("test21BasicTimeStampDSA");
        final int workerId = WORKER20.getId();
        try {
            // Setup signer
            final File keystore = new File(getSignServerHome(), "res/test/dss10/dss10_tssigner6dsa.jks");
            if (!keystore.exists()) {
                throw new FileNotFoundException(keystore.getAbsolutePath());
            }
            addJKSDummySigner(TimeStampSigner.class.getName(), workerId, "TestTimeStampJKSDSA", keystore, "foo123", "mykey");
            workerSession.setWorkerProperty(workerId, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(workerId, "ACCEPTANYPOLICY", "true");
            workerSession.setWorkerProperty(workerId, "SIGNATUREALGORITHM", "SHA1WithDSA");
            workerSession.reloadConfiguration(workerId);

            // Test signing
            TimeStampResponse response = assertSuccessfulTimestamp(WORKER20, true);

            // Test that it is using the right algorithm
            TimeStampToken token = response.getTimeStampToken();
            SignerInformation si = token.toCMSSignedData().getSignerInfos().getSigners().iterator().next();
            assertEquals("sha1withdsa", "1.2.840.10040.4.3", si.getEncryptionAlgOID());
        } finally {
            removeWorker(workerId);
        }
    }

    /**
     * Test with requestData of zero length. Shall give an IllegalRequestException.
     */
    @Test
    public void test22EmptyRequest() {
        LOG.info("test22EmptyRequest");
        int reqid = RANDOM.nextInt();
        byte[] requestBytes = new byte[0];

        GenericSignRequest signRequest =
                new GenericSignRequest(reqid, requestBytes);

        try {
            processSession.process(WORKER1, signRequest, new RemoteRequestContext());
        } catch (IllegalRequestException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e.getClass().getName());
        }
    }

    /**
     * Test with an invalid requestData. Shall give an IllegalRequestException.
     */
    @Test
    public void test23BogusRequest() {
        LOG.info("test23BogusRequest");
        int reqid = RANDOM.nextInt();
        byte[] requestBytes = "bogus request".getBytes();

        GenericSignRequest signRequest =
                new GenericSignRequest(reqid, requestBytes);

        try {
            processSession.process(WORKER1, signRequest, new RemoteRequestContext());
        } catch (IllegalRequestException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e.getClass().getName());
        }
    }

    /**
     * Test with setting requestData to null. Shall give an IllegalRequestException.
     */
    @Test
    public void test24NullRequest() {
        LOG.info("test24NullRequest");
        int reqid = RANDOM.nextInt();
        byte[] requestBytes = "bogus request".getBytes();

        GenericSignRequest signRequest =
                new GenericSignRequest(reqid, requestBytes);

        try {
            processSession.process(WORKER1, signRequest, new RemoteRequestContext());
        } catch (IllegalRequestException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e.getClass().getName());
        }
    }

    /**
     * Test that the default behavior is to include the status string in the TSA response.
     */
    @Test
    public void test25StatusStringIncluded() throws Exception {
        LOG.info("test25StatusStringIncluded");
        // Test signing
        final TimeStampResponse response = assertSuccessfulTimestamp(WORKER1, true);

        assertEquals("Operation Okay", response.getStatusString());
    }

    /**
     * Test that setting the INCLUDESTATUSSTRING property to false results in no status string
     * in the TSA response.
     */
    @Test
    public void test26StatusStringExcluded() throws Exception {
        LOG.info("test26StatusStringExcluded");
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.INCLUDESTATUSSTRING, "FALSE");
        workerSession.reloadConfiguration(WORKER1.getId());

        final TimeStampResponse response = assertSuccessfulTimestamp(WORKER1, true);

        assertNull(response.getStatusString());
    }

    /**
     * Test that the default behavior on rejection is to include a status string.
     */
    @Test
    public void test27StatusStringIncludedFailure() throws Exception {
        LOG.info("test27StatusStringIncludedFailure");
        // WORKER2 has ACCEPTEDPOLICIES=1.2.3
        // Create an request with another policy (1.2.3.5 != 1.2.3)
        final TimeStampRequest timeStampRequest = new TimeStampRequest(
                Base64.decode(REQUEST_WITH_POLICY1235.getBytes()));

        final byte[] requestBytes = timeStampRequest.getEncoded();

        final GenericSignRequest signRequest = new GenericSignRequest(13,
                requestBytes);

        final GenericSignResponse res = (GenericSignResponse) processSession.process(
                WORKER2, signRequest, new RemoteRequestContext());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(res.getProcessedData());

        assertNotNull(timeStampResponse.getStatusString());
    }

    /**
     * Test that setting the INCLUDESTATUSSTRING property to false results in no status string
     * on rejection.
     */
    @Test
    public void test28StatusStringExcludedFailure() throws Exception {
        LOG.info("test28StatusStringExcludedFailure");
        workerSession.setWorkerProperty(WORKER2.getId(), TimeStampSigner.INCLUDESTATUSSTRING, "FALSE");
        workerSession.reloadConfiguration(WORKER2.getId());
        // WORKER2 has ACCEPTEDPOLICIES=1.2.3
        // Create an request with another policy (1.2.3.5 != 1.2.3)
        final TimeStampRequest timeStampRequest = new TimeStampRequest(
                Base64.decode(REQUEST_WITH_POLICY1235.getBytes()));

        final byte[] requestBytes = timeStampRequest.getEncoded();

        final GenericSignRequest signRequest = new GenericSignRequest(13,
                requestBytes);

        final GenericSignResponse res = (GenericSignResponse) processSession.process(
                WORKER2, signRequest, new RemoteRequestContext());

        final TimeStampResponse timeStampResponse = new TimeStampResponse(res.getProcessedData());

        assertNotEquals("Operation Okey", timeStampResponse.getStatusString());
    }

    /**
     * Test that omitting a default policy OID results in the correct fatal error.
     */
    @Test
    public void test29NoDefaultPolicyOID() throws Exception {
        LOG.info("test29NoDefaultPolicyOID");
        workerSession.removeWorkerProperty(WORKER1.getId(), TimeStampSigner.DEFAULTTSAPOLICYOID);
        workerSession.reloadConfiguration(WORKER1.getId());

        final WorkerStatus status = workerSession.getStatus(WORKER1);
        final List<String> errors = status.getFatalErrors();

        assertTrue("Should mention missing default policy OID: " + errors,
                errors.contains("No default TSA policy OID has been configured"));

        // restore
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.DEFAULTTSAPOLICYOID, "1.2.3");
        workerSession.reloadConfiguration(WORKER1.getId());
    }

    /**
     * Test that setting an invalid default policy OID results in the correct fatal error.
     */
    @Test
    public void test30BogusDefaultPolicyOID() throws Exception {
        LOG.info("test30BogusDefaultPolicyOID");
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.DEFAULTTSAPOLICYOID, "foobar");
        workerSession.reloadConfiguration(WORKER1.getId());

        final WorkerStatus status = workerSession.getStatus(WORKER1);
        final String errors = status.getFatalErrors().toString();

        assertTrue("Should mention missing default policy OID: " + errors,
                errors.contains("TSA policy OID foobar is invalid"));

        // restore
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.DEFAULTTSAPOLICYOID, "1.2.3");
        workerSession.reloadConfiguration(WORKER1.getId());
    }

    /**
     * Test that the default behavior is to not include the TSA field.
     */
    @Test
    public void test31NoTSAName() throws Exception {
        LOG.info("test31NoTSAName");
        // Test signing
        final TimeStampResponse response = assertSuccessfulTimestamp(WORKER1, true);

        assertNull("No TSA set", response.getTimeStampToken().getTimeStampInfo().getTsa());
    }

    /**
     * Test setting the TSA worker property.
     */
    @Test
    public void test32ExplicitTSAName() throws Exception {
        LOG.info("test32ExplicitTSAName");
        workerSession.removeWorkerProperty(WORKER1.getId(), TimeStampSigner.TSA_FROM_CERT);
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.TSA, "CN=test");
        workerSession.reloadConfiguration(WORKER1.getId());

        final TimeStampResponse response = assertSuccessfulTimestamp(WORKER1, true);
        final GeneralName name = response.getTimeStampToken().getTimeStampInfo().getTsa();
        final GeneralName expectedName = new GeneralName(new X500Name("CN=test"));

        assertEquals("TSA included", expectedName, name);

        // restore
        workerSession.removeWorkerProperty(WORKER1.getId(), TimeStampSigner.TSA);
        workerSession.reloadConfiguration(WORKER1.getId());
    }

    /**
     * Test using the TSA_FROM_CERT property to set the TSA name from
     * the signing cert.
     */
    @Test
    public void test34TSANameFromCert() throws Exception {
        LOG.info("test34TSANameFromCert");
        workerSession.removeWorkerProperty(WORKER1.getId(), TimeStampSigner.TSA);
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.TSA_FROM_CERT, "true");
        workerSession.reloadConfiguration(WORKER1.getId());

        final TimeStampResponse response = assertSuccessfulTimestamp(WORKER1, true);
        final GeneralName name = response.getTimeStampToken().getTimeStampInfo().getTsa();
        final GeneralName expectedName = new GeneralName(new X500Name("CN=ts00003,OU=Testing,O=SignServer,C=SE"));

        assertEquals("TSA included", expectedName, name);

        final GeneralName certName =
               new GeneralName(new JcaX509CertificateHolder((X509Certificate) workerSession.getSignerCertificate(WORKER1)).getSubject());
        assertArrayEquals("TSA name content equals cert", certName.getEncoded(), name.getEncoded());

        // restore
        workerSession.removeWorkerProperty(WORKER1.getId(), TimeStampSigner.TSA_FROM_CERT);
        workerSession.reloadConfiguration(WORKER1.getId());
    }

    /**
     * Test setting both the TSA and TSA_FROM_CERT property, should result in an error.
     */
    @Test
    public void test35TSANameExplicitAndFromCert() throws Exception {
        LOG.info("test35TSANameExplicitAndFromCert");
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.TSA, "CN=test");
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.TSA_FROM_CERT, "true");
        workerSession.reloadConfiguration(WORKER1.getId());

        final WorkerStatus status = workerSession.getStatus(WORKER1);
        final List<String> errors = status.getFatalErrors();

        assertTrue("Should mention conflicting TSA properties: " + errors,
                errors.contains("Can not set " + TimeStampSigner.TSA_FROM_CERT + " to true and set " +
                        TimeStampSigner.TSA + " worker property at the same time"));

        // restore
        workerSession.removeWorkerProperty(WORKER1.getId(), TimeStampSigner.TSA);
        workerSession.removeWorkerProperty(WORKER1.getId(), TimeStampSigner.TSA_FROM_CERT);
        workerSession.reloadConfiguration(WORKER1.getId());
    }

    /**
     * Test that excluding signingTime signed CMS attribute works.
     */
    @Test
    public void test36noSigningTimeAttribute() throws Exception {
        LOG.info("test36noSigningTimeAttribute");
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.INCLUDESIGNINGTIMEATTRIBUTE, "false");
        workerSession.reloadConfiguration(WORKER1.getId());

        assertSuccessfulTimestamp(WORKER1, false);
    }

    /**
     * Test that explicitly including the signingTime signed attribute works.
     */
    @Test
    public void test37explicitlyIncludeSigningTime() throws Exception {
        LOG.info("test37explicitlyIncludeSigningTime");
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.INCLUDESIGNINGTIMEATTRIBUTE, "true");
        workerSession.reloadConfiguration(WORKER1.getId());

        assertSuccessfulTimestamp(WORKER1, true);
    }

    /**
     * Return the ASN1Sequence encapsulated in the tSTInfo structure.
     *
     * @param res TSA response data.
     * @return The encoded sequence in TSTInfo (see the TSTInfo class).
     */
    private ASN1Sequence extractTstInfoSeq(final byte[] res) {
        final ASN1Sequence seq1 = ASN1Sequence.getInstance(res);
        final ASN1Sequence signedData = ASN1Sequence.getInstance(seq1.getObjectAt(1));
        final ASN1TaggedObject tag = ASN1TaggedObject.getInstance(signedData.getObjectAt(1));
        final ASN1Sequence seq2 = ASN1Sequence.getInstance(tag.getObject());
        final ASN1Sequence seq3 = ASN1Sequence.getInstance(seq2.getObjectAt(2));
        final ASN1TaggedObject tag2 = ASN1TaggedObject.getInstance(seq3.getObjectAt(1));
        final ASN1OctetString data = ASN1OctetString.getInstance(tag2.getObject());

        return ASN1Sequence.getInstance(data.getOctets());
    }

    /**
     * Test that ordering is not included by default.
     */
    @Test
    public void test38orderingDefault() throws Exception {
        LOG.info("test38orderingDefault");
        // reset ORDERING property
        workerSession.removeWorkerProperty(WORKER1.getId(), TimeStampSigner.ORDERING);
        workerSession.reloadConfiguration(WORKER1.getId());

        final byte[] res = getResponseData(WORKER1);
        final ASN1Sequence seq = extractTstInfoSeq(res);

        try {
            ASN1Boolean.getInstance(seq.getObjectAt(5));
        } catch (IllegalArgumentException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName() + ": " + e.getMessage());
        }
    }

    /**
     * Test that setting ordering to "true" results in a correct tstInfo sequence.
     */
    @Test
    public void test39orderingTrue() throws Exception {
        LOG.info("test39orderingTrue");
        // reset ORDERING property
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.ORDERING, "true");
        workerSession.reloadConfiguration(WORKER1.getId());

        final byte[] res = getResponseData(WORKER1);
        final ASN1Sequence seq = extractTstInfoSeq(res);
        final ASN1Encodable o = seq.getObjectAt(5);

        try {
            // when ordering isn't included, the 6:th element in the tstInfo sequence should be the nonce
            final ASN1Boolean b = ASN1Boolean.getInstance(o);
            assertEquals("Ordering should be set to true", ASN1Boolean.TRUE, b);
        } catch (IllegalArgumentException e) {
            fail("Ordering should be included");
        } catch (Exception e) {
            fail("Unexpected exception");
        } finally {
            workerSession.removeWorkerProperty(WORKER1.getId(), TimeStampSigner.ORDERING);
            workerSession.reloadConfiguration(WORKER1.getId());
        }
    }

    /**
     * Test that by default (when not setting INCLUDEORDERING to "true") ordering is not
     * included ordering is set to "false".
     */
    @Test
    public void test40orderingFalse() throws Exception {
        LOG.info("test40orderingFalse");
        // reset ORDERING property
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.ORDERING, "false");
        workerSession.reloadConfiguration(WORKER1.getId());

        final byte[] res = getResponseData(WORKER1);
        final ASN1Sequence seq = extractTstInfoSeq(res);
        final ASN1Encodable o = seq.getObjectAt(5);

        try {
            // when ordering isn't included, the 6:th element in the tstInfo sequence should be the nonce
            ASN1Boolean.getInstance(o);
            fail("Ordering shouldn't included when ORDERING = false");
        } catch (IllegalArgumentException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception");
        } finally {
            workerSession.removeWorkerProperty(WORKER1.getId(), TimeStampSigner.ORDERING);
            workerSession.reloadConfiguration(WORKER1.getId());
        }
    }

    /**
     * Test that the ordering field is included when ORDERING == true.
     */
    @Test
    public void test42IncludeOrderingOrderingTrue() throws Exception {
        LOG.info("test42IncludeOrderingOrderingTrue");
        // reset ORDERING property
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.ORDERING, "true");
        workerSession.reloadConfiguration(WORKER1.getId());

        final byte[] res = getResponseData(WORKER1);
        final ASN1Sequence seq = extractTstInfoSeq(res);
        final ASN1Encodable o = seq.getObjectAt(5);

        try {
            final ASN1Boolean b = ASN1Boolean.getInstance(o);
            assertEquals("Ordering should be set to true", ASN1Boolean.TRUE, b);
        } catch (IllegalArgumentException e) {
            fail("Ordering should be included");
        } catch (Exception e) {
            fail("Unexpected exception");
        } finally {
            workerSession.removeWorkerProperty(WORKER1.getId(), TimeStampSigner.ORDERING);
            workerSession.reloadConfiguration(WORKER1.getId());
        }
    }

    /**
     * Test that the ordering field is not included when ORDERING == false.
     */
    @Test
    public void test43NotIncludeOrderingOrderingFalse() throws Exception {
        LOG.info("test43NotIncludeOrderingOrderingFalse");
        // reset ORDERING property
        workerSession.setWorkerProperty(WORKER1.getId(), TimeStampSigner.ORDERING, "false");
        workerSession.reloadConfiguration(WORKER1.getId());

        final byte[] res = getResponseData(WORKER1);
        final ASN1Sequence seq = extractTstInfoSeq(res);
        final ASN1Encodable o = seq.getObjectAt(5);

        try {
            ASN1Boolean.getInstance(o);
            fail("Ordering should not be included");
        } catch (IllegalArgumentException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception");
        } finally {
            workerSession.removeWorkerProperty(WORKER1.getId(), TimeStampSigner.ORDERING);
            workerSession.reloadConfiguration(WORKER1.getId());
        }
    }

    /**
     * Test that setting INCLUDE_CERTIFICATE_LEVELS to 0 is not supported.
     */
    @Test
    public void test45IncludeCertificateLevels0NotAllowed() throws Exception {
        LOG.info("test45IncludeCertificateLevels0NotAllowed");
        try {
           workerSession.setWorkerProperty(WORKER1.getId(), WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS, "0");
           workerSession.reloadConfiguration(WORKER1.getId());

           final List<String> errors = workerSession.getStatus(WORKER1).getFatalErrors();

           assertTrue("Should contain configuration error",
                   errors.contains("Illegal value for property " +
                                   WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS +
                                   ". Only numbers >= 1 supported."));
        } finally {
           workerSession.removeWorkerProperty(WORKER1.getId(), WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS);
           workerSession.reloadConfiguration(WORKER1.getId());
        }
    }

    /**
     * Test timestamping with certificate digest method SHA1.
     * Checks that the ESSCertID attribute (not v2) is used in the response.
     */
    @Test
    public void test46CertificateDigestMethodSHA1() throws Exception {
        LOG.info("test46CertificateDigestMethodSHA1");
    	testWithHash(TSPAlgorithms.SHA256, "SHA1", false);
    }

    /**
     * Test with certificate digest method SHA256 explicitly set as a worker
     * property.
     * Also checks that the v2 signing cert attribute is included.
     */
    @Test
    public void test47CertificateDigestMethodSHA256Explicit() throws Exception {
        LOG.info("test47CertificateDigestMethodSHA256Explicit");
        testWithHash(TSPAlgorithms.SHA256, "SHA256", true);
    }

    /**
     * Test with certificate digest method SHA384.
     * Also checks that the v2 signing cert attribute is included.
     */
    @Test
    public void test48CertificateDigestMethodSHA384() throws Exception {
        LOG.info("test48CertificateDigestMethodSHA384");
        testWithHash(TSPAlgorithms.SHA256, "SHA384", true);
    }

    /**
     * Test with certificate digest method SHA512.
     * Also checks that the v2 signing cert attribute is included.
     */
    @Test
    public void test49CertificateDigestMethodSHA512() throws Exception {
        LOG.info("test49CertificateDigestMethodSHA512");
        testWithHash(TSPAlgorithms.SHA256, "SHA512", true);
    }

    /**
     * Test with certificate digest method SHA224.
     * Also checks that the v2 signing cert attribute is used.
     */
    @Test
    public void test50CertificateDigestMethodSHA224() throws Exception {
        LOG.info("test50CertificateDigestMethodSHA224");
        testWithHash(TSPAlgorithms.SHA256, "SHA224", true);
    }

    /**
     * Test with certificate digest method SHA-512 (specified with a dash).
     * Also checks that the v2 signing cert attribute is included.
     */
    @Test
    public void test51CertificateDigestMethodSHA512WithDash() throws Exception {
        LOG.info("test51CertificateDigestMethodSHA512WithDash");
        testWithHash(TSPAlgorithms.SHA256, "SHA-512", true);
    }

    private void assertTokenGranted(WorkerIdentifier wi) throws Exception {
        TimeStampRequestGenerator timeStampRequestGenerator =
                    new TimeStampRequestGenerator();
        timeStampRequestGenerator.setCertReq(true);
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest =
                new GenericSignRequest(123124, requestBytes);
        try {
            final GenericSignResponse res = (GenericSignResponse) processSession.process(
                    wi, signRequest, new RemoteRequestContext());

            final TimeStampResponse timeStampResponse = new TimeStampResponse(res.getProcessedData());
            timeStampResponse.validate(timeStampRequest);

            assertEquals(PKIStatus.GRANTED, timeStampResponse.getStatus());
        } catch (CryptoTokenOfflineException ex) {
            fail(ex.getMessage());
        }
    }

    private void assertTokenNotGranted(WorkerIdentifier wi) throws Exception {
        TimeStampRequestGenerator timeStampRequestGenerator =
                    new TimeStampRequestGenerator();
        timeStampRequestGenerator.setCertReq(true);
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(
                TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest =
                new GenericSignRequest(123124, requestBytes);
        try {
            final GenericSignResponse res = (GenericSignResponse) processSession.process(
                    wi, signRequest, new RemoteRequestContext());

            final TimeStampResponse timeStampResponse = new TimeStampResponse(res.getProcessedData());
            timeStampResponse.validate(timeStampRequest);

            assertNotEquals(PKIStatus.GRANTED, timeStampResponse.getStatus());
        } catch (CryptoTokenOfflineException ignored) { //NOPMD
            // OK
        }
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        LOG.info("test99TearDownDatabase");
        removeWorker(WORKER1.getId());
        removeWorker(WORKER2.getId());
        removeWorker(WORKER3.getId());
        removeWorker(WORKER4.getId());
        removeWorker(WORKER5.getId());
    }
}
