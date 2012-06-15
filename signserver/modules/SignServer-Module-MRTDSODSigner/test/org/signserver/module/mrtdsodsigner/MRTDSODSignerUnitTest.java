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
package org.signserver.module.mrtdsodsigner;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.jce.ECKeyUtil;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.module.mrtdsodsigner.jmrtd.SODFile;
import org.signserver.server.cryptotokens.HardCodedCryptoTokenAliases;
import org.signserver.test.utils.mock.GlobalConfigurationSessionMock;
import org.signserver.test.utils.mock.WorkerSessionMock;

/**
 * Unit tests for MRTDSODSigner.
 *
 * This tests uses a mockup and does not require an running application
 * server. Tests that require that can be placed among the system tests.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class MRTDSODSignerUnitTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            MRTDSODSignerUnitTest.class.getName());

    private static final String AUTHTYPE = "AUTHTYPE";
    private static final String CRYPTOTOKEN_CLASSNAME
            = "org.signserver.server.cryptotokens.P12CryptoToken";
    private static final String NAME = "NAME";

    /** Worker7897: Default algorithms, default hashing setting. */
    private static final int WORKER1 = 7897;

    /** Worker7898: SHA512, default hashing setting. */
    private static final int WORKER2 = 7898;

    /** Worker7899: Default algorithms, DODATAGROUPHASHING=true. */
    private static final int WORKER3 = 7899;

    /** Worker7900: SHA512, DODATAGROUPHASHING=true. */
    private static final int WORKER4 = 7900;

    /** Worker7910: ldsVersion=1.8, unicodeVersion=4.0.0. */
    private static final int WORKER5 = 7910;

    /** Worker7911: SHA1withRSAandMGF1 */
    private static final int WORKER11 = 7911;

    /** Worker7912: SHA256withRSAandMGF1 */
    private static final int WORKER12 = 7912;

    /** Worker7913: SHA384withRSAandMGF1 */
    private static final int WORKER13 = 7913;

    /** Worker7914: SHA512withRSAandMGF1 */
    private static final int WORKER14 = 7914;

    /** Worker7915: SHA1, SHA256withRSAandMGF1 */
    private static final int WORKER15 = 7915;

    /** Worker7916: The other DN order. */
    private static final int WORKER16 = 7916;

    /** Worker7917: Certificate chain with SHA256withRSAandMGF1. */
    private static final int WORKER17 = 7917;

    /** Worker7918: SHA256WithECDSA explicit ECC parameters in the DS cert. */
    private static final int WORKER18 = 7918;

    private static final String KEYSTOREPATH = "KEYSTOREPATH";
    private static final String KEYSTOREPASSWORD = "KEYSTOREPASSWORD";

    private File keystore1;
    private String keystore1Password;

    private File keystore2;
    private String keystore2Password;

    private File keystore3;
    private String keystore3Password;

    private File keystore4;
    private String keystore4Password;
    
    private IGlobalConfigurationSession.IRemote globalConfig;
    private IWorkerSession.IRemote workerSession;

    
    public MRTDSODSignerUnitTest() {
        SignServerUtil.installBCProvider();
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        // Normal keystore
        keystore1 = new File("test/demods1.p12");
        if (!keystore1.exists()) {
            throw new FileNotFoundException("No such keystore: "
                    + keystore1.getAbsolutePath());
        }
        keystore1Password = "foo123";

        // Keystore with certificate not using LDAP DN ordering
        keystore2 = new File("test/reversedendentity2.p12");
        if (!keystore2.exists()) {
            throw new FileNotFoundException("No such keystore: "
                    + keystore2.getAbsolutePath());
        }
        keystore2Password = "foo123";

        // Normal keystore
        keystore3 = new File("test/demods41.p12");
        if (!keystore3.exists()) {
            throw new FileNotFoundException("No such keystore: "
                    + keystore3.getAbsolutePath());
        }
        keystore3Password = "foo123";

        // Keystore with ECC using named parameters
        keystore4 = new File("test/demodsecc1.p12");
        if (!keystore4.exists()) {
            throw new FileNotFoundException("No such keystore: "
                    + keystore4.getAbsolutePath());
        }
        keystore4Password = "foo123";

        setupWorkers();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Creates and verifies a simple SODFile
     * @throws Exception
     */
    public void test01SODFile() throws Exception {
    	Map<Integer, byte[]> dataGroupHashes = new HashMap<Integer, byte[]>();
    	dataGroupHashes.put(Integer.valueOf(1), "12345".getBytes());
    	dataGroupHashes.put(Integer.valueOf(4), "abcdef".getBytes());

    	// RSA
    	KeyPair keys = KeyTools.genKeys("1024", "RSA");
    	X509Certificate cert = CertTools.genSelfCert("CN=mrtdsodtest", 33, null, keys.getPrivate(), keys.getPublic(), "SHA256WithRSA", false);
        SODFile sod = new SODFile("SHA256", "SHA256withRSA", dataGroupHashes, keys.getPrivate(), cert);
        assertNotNull(sod);
        boolean verify = sod.checkDocSignature(cert);
        assertTrue(verify);
        byte[] encoded = sod.getEncoded();
        SODFile sod2 = new SODFile(new ByteArrayInputStream(encoded));
        verify = sod2.checkDocSignature(cert);
        assertTrue(verify);
        
        // ECC
    	KeyPair keysec = KeyTools.genKeys("secp256r1", "ECDSA");
        PublicKey publicKey = ECKeyUtil.publicToExplicitParameters(keysec.getPublic(), "BC");
    	X509Certificate certec = CertTools.genSelfCert("CN=mrtdsodtest", 33, null, keysec.getPrivate(), publicKey, "SHA256WithECDSA", false);
        SODFile sodec = new SODFile("SHA256", "SHA256withECDSA", dataGroupHashes, keysec.getPrivate(), cert);
        assertNotNull(sodec);
        boolean verifyec = sodec.checkDocSignature(certec);
        assertTrue(verifyec);
        byte[] encodedec = sodec.getEncoded();
        SODFile sod2ec = new SODFile(new ByteArrayInputStream(encodedec));
        verifyec = sod2ec.checkDocSignature(certec);
        assertTrue(verifyec);

    }

    /**
     * Requests signing of some data group hashes, using two different signers
     * with different algorithms and verifies the result.
     * @throws Exception
     */
    public void test02SignData() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        signHelper(WORKER1, 12, dataGroups1, false, "SHA256", "SHA256withRSA");

        // DG3, DG7, DG8, DG13 and default values
        Map<Integer, byte[]> dataGroups2 = new LinkedHashMap<Integer, byte[]>();
        dataGroups2.put(3, digestHelper("Dummy Value 3".getBytes(), "SHA256"));
        dataGroups2.put(7, digestHelper("Dummy Value 4".getBytes(), "SHA256"));
        dataGroups2.put(8, digestHelper("Dummy Value 5".getBytes(), "SHA256"));
        dataGroups2.put(13, digestHelper("Dummy Value 6".getBytes(), "SHA256"));
        signHelper(WORKER1, 13, dataGroups2, false, "SHA256", "SHA256withRSA");

        // DG1, DG2 with the other worker which uses SHA512 and SHA512withRSA
        Map<Integer, byte[]> dataGroups3 = new LinkedHashMap<Integer, byte[]>();
        dataGroups3.put(1, digestHelper("Dummy Value 7".getBytes(), "SHA512"));
        dataGroups3.put(2, digestHelper("Dummy Value 8".getBytes(), "SHA512"));
        signHelper(WORKER2, 14, dataGroups3, false, "SHA512", "SHA512withRSA");
        
        // DG1, DG2 with the other worker which uses SHA512 and SHA512withRSA
        Map<Integer, byte[]> dataGroups4 = new LinkedHashMap<Integer, byte[]>();
        dataGroups4.put(1, digestHelper("Dummy Value 9".getBytes(), "SHA256"));
        dataGroups4.put(2, digestHelper("Dummy Value 10".getBytes(), "SHA256"));
        signHelper(WORKER18, 14, dataGroups3, false, "SHA256", "SHA256withECDSA");
    }

    /**
     * Requests signing of some data groups, using two different signers
     * with different algorithms and verifies the result. The signer does the
     * hashing.
     * @throws Exception
     */
    public void test03SignUnhashedData() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, "Dummy Value 1".getBytes());
        dataGroups1.put(2, "Dummy Value 2".getBytes());
        signHelper(WORKER3, 15, dataGroups1, true, "SHA256", "SHA256withRSA");

        // DG3, DG7, DG8, DG13 and default values
        Map<Integer, byte[]> dataGroups2 = new LinkedHashMap<Integer, byte[]>();
        dataGroups2.put(3, "Dummy Value 3".getBytes());
        dataGroups2.put(7, "Dummy Value 4".getBytes());
        dataGroups2.put(8, "Dummy Value 5".getBytes());
        dataGroups2.put(13, "Dummy Value 6".getBytes());
        signHelper(WORKER3, 16, dataGroups2, true, "SHA256", "SHA256withRSA");

        // DG1, DG2 with the other worker which uses SHA512 and SHA512withRSA
        Map<Integer, byte[]> dataGroups3 = new LinkedHashMap<Integer, byte[]>();
        dataGroups3.put(1, "Dummy Value 7".getBytes());
        dataGroups3.put(2, "Dummy Value 8".getBytes());
        signHelper(WORKER4, 17, dataGroups3, true, "SHA512", "SHA512withRSA");
    }

    public void test04LdsConfigVersion17_ok() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        final SODFile sod = signHelper(WORKER1, 12, dataGroups1, false,
                "SHA256", "SHA256withRSA");

        // ASN.1 Dump SODFile
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(sod.getEncoded()));
        ASN1Object object = in.readObject();
        LOG.info("Object: " + ASN1Dump.dumpAsString(object, true));

//        // ANS.1 Dump LDSSecurityObject
//        in = new ASN1InputStream(new ByteArrayInputStream(sod.getSecurityObject()));
//        object = in.readObject();
//        LOG.info("LDSSecurityObject: " + ASN1Dump.dumpAsString(object, true));

        assertNull("LDS version", sod.getLdsVersion());
        assertNull("Unicode version", sod.getUnicodeVersion());
    }

    public void test05LdsConfigVersion18_ok() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        final SODFile sod = signHelper(WORKER5, 12, dataGroups1, false,
                "SHA256", "SHA256withRSA");

        // ASN.1 Dump
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(sod.getEncoded()));
        ASN1Object object = in.readObject();
        LOG.info("Object: " + ASN1Dump.dumpAsString(object, true));

//        // ANS.1 Dump LDSSecurityObject
//        in = new ASN1InputStream(new ByteArrayInputStream(sod.getSecurityObject()));
//        object = in.readObject();
//        LOG.info("LDSSecurityObject: " + ASN1Dump.dumpAsString(object, true));

        assertEquals("LDS version", "0108", sod.getLdsVersion());
        assertEquals("Unicode version", "040000", sod.getUnicodeVersion());
    }
    
    public void test05LdsConfigVersion18_noUnicode() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));

        // Missing unicode version
        workerSession.removeWorkerProperty(WORKER5, "UNICODEVERSION");
        workerSession.reloadConfiguration(WORKER5);

        try {
            signHelper(WORKER5, 12, dataGroups1, false,
                "SHA256", "SHA256withRSA");
            fail("Should have failed");
        } catch (IllegalRequestException ignored) {
            // OK
            LOG.debug("Message was: " + ignored.getMessage());
        }
    }

    public void test05LdsConfigVersionUnsupported() throws Exception {

        // Unsupported version
        workerSession.setWorkerProperty(WORKER5, "LDSVERSION", "4711");
        workerSession.reloadConfiguration(WORKER5);

        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        try {
            signHelper(WORKER5, 12, dataGroups1, false, "SHA256",
                    "SHA256withRSA");
            fail("Should have failed");
        } catch (IllegalRequestException ignored) {
            // OK
            LOG.debug("Message was: " + ignored.getMessage());
        }
    }

    /**
     * Requests signing of some data group hashes and verifies the result.
     * @throws Exception
     */
    public void test06SignData_SHA1withRSAandMGF1() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA1"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA1"));
        signHelper(WORKER11, 12, dataGroups1, false, "SHA1",
                "SHA1withRSAandMGF1");
    }
    
    /**
     * Requests signing of some data group hashes and verifies the result.
     * @throws Exception
     */
    public void test06SignData_SHA256withRSAandMGF1() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        signHelper(WORKER12, 12, dataGroups1, false, "SHA256",
                "SHA256withRSAandMGF1");

        // DG1, DG2 and default values, other hash than in algorithm
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA1"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA1"));
        signHelper(WORKER15, 12, dataGroups1, false, "SHA1",
                "SHA256withRSAandMGF1");
    }

    /**
     * Requests signing of some data group hashes and verifies the result. Uses
     * certificate chain with SHA256withRSAandMGF1.
     * @throws Exception
     */
    public void test06SignData_SHA256withRSAandMGF1_certs() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA256"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA256"));
        signHelper(WORKER17, 12, dataGroups1, false, "SHA256",
                "SHA256withRSAandMGF1");
    }

    /**
     * Requests signing of some data group hashes and verifies the result.
     * @throws Exception
     */
    public void test06SignData_SHA384withRSAandMGF1() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA384"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA384"));
        signHelper(WORKER13, 12, dataGroups1, false, "SHA384",
                "SHA384withRSAandMGF1");
    }

    /**
     * Requests signing of some data group hashes and verifies the result.
     * @throws Exception
     */
    public void test06SignData_SHA512withRSAandMGF1() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA512"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA512"));
        signHelper(WORKER14, 12, dataGroups1, false, "SHA512",
                "SHA512withRSAandMGF1");
    }

    /**
     * Tests that the order of the issuer DN in the SignerInfo is the same as in
     * the certificate. Tests with a certificate in "LDAP DN order"
     * (the default in EJBCA).
     * @throws Exception in case of error.
     */
    public void test07DNOrder() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA1"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA1"));
        SODFile sod = signHelper(WORKER11, 12, dataGroups1, false, "SHA1",
                "SHA1withRSAandMGF1");

//        System.out.println("SOD Issuer: "
//                + sod.getIssuerX500Principal().getName());
//        System.out.println("CER Issuer: " + sod.getDocSigningCertificate()
//                .getIssuerX500Principal().getName());
//        System.out.println("Object: " + ASN1Dump.dumpAsString(
//                new ASN1InputStream(new ByteArrayInputStream(
//                sod.getEncoded())).readObject(), true));

        // The real asn.1 order in the cert is CN=DemoCSCA1, C=SE
        assertEquals("C=SE,CN=DemoCSCA1", sod.getIssuerX500Principal().getName());
        assertEquals("C=SE,CN=DemoCSCA1", sod.getDocSigningCertificate().getIssuerX500Principal().getName());
        assertEquals("C=SE, CN=DemoCSCA1", sod.getDocSigningCertificate().getIssuerDN().getName());

        // Make sure it matches in all ways
        assertEquals("DN should match", sod.getIssuerX500Principal().getName(),
            sod.getDocSigningCertificate().getIssuerX500Principal().getName());
        assertTrue("DN should match", sod.getIssuerX500Principal().equals(sod.getDocSigningCertificate().getIssuerX500Principal()));
        // The DER encoding should be the same
        Arrays.equals(sod.getIssuerX500Principal().getEncoded(), sod.getDocSigningCertificate().getEncoded());
    }

    /**
     * Tests that the order of the issuer DN in the SignerInfo is the same as in
     * the certificate. Tests with a certificate not in "LDAP DN order".
     * @throws Exception in case of error.
     */
    public void test07DNOrderReversed() throws Exception {
        // DG1, DG2 and default values
        Map<Integer, byte[]> dataGroups1 = new LinkedHashMap<Integer, byte[]>();
        dataGroups1.put(1, digestHelper("Dummy Value 1".getBytes(), "SHA1"));
        dataGroups1.put(2, digestHelper("Dummy Value 2".getBytes(), "SHA1"));
        SODFile sod = signHelper(WORKER16, 12, dataGroups1, false, "SHA1",
                "SHA1withRSAandMGF1");

//        System.out.println("SOD Issuer: "
//                + sod.getIssuerX500Principal().getName());
//        System.out.println("CER Issuer: " + sod.getDocSigningCertificate()
//                .getIssuerX500Principal().getName());
//        System.out.println("Object reversed: " + ASN1Dump.dumpAsString(
//                new ASN1InputStream(new ByteArrayInputStream(
//                sod.getEncoded())).readObject(), true));

        // The real asn.1 order in the cert is C=SE,O=Reversed Org,CN=ReversedCA2
        assertEquals("CN=ReversedCA2,O=Reversed Org,C=SE", sod.getIssuerX500Principal().getName());
        assertEquals("CN=ReversedCA2,O=Reversed Org,C=SE", sod.getDocSigningCertificate().getIssuerX500Principal().getName());
        assertEquals("CN=ReversedCA2, O=Reversed Org, C=SE", sod.getDocSigningCertificate().getIssuerDN().getName());
        
        // Make sure it matches in all ways
        assertEquals("DN should match", sod.getIssuerX500Principal().getName(),
            sod.getDocSigningCertificate().getIssuerX500Principal().getName());
        assertTrue("DN should match", sod.getIssuerX500Principal().equals(sod.getDocSigningCertificate().getIssuerX500Principal()));
        // The DER encoding should be the same
        Arrays.equals(sod.getIssuerX500Principal().getEncoded(), sod.getDocSigningCertificate().getEncoded());
    }
    

    private SODFile signHelper(int workerId, int requestId, Map<Integer, byte[]> dataGroups, boolean signerDoesHashing, String digestAlg, String sigAlg) throws Exception {

        // Create expected hashes
    	Map<Integer, byte[]> expectedHashes;
    	if(signerDoesHashing) {
            MessageDigest d = MessageDigest.getInstance(digestAlg, "BC");
            expectedHashes = new HashMap<Integer, byte[]>();
            for(Map.Entry<Integer, byte[]> entry : dataGroups.entrySet()) {
                expectedHashes.put(entry.getKey(), d.digest(entry.getValue()));
                d.reset();
            }
    	} else {
            expectedHashes = dataGroups;
    	}

        SODSignResponse res = (SODSignResponse) workerSession.process(workerId,
                new SODSignRequest(requestId, dataGroups),
                new RequestContext());
        assertNotNull(res);
        assertEquals(requestId, res.getRequestID());
        Certificate signercert = res.getSignerCertificate();
        assertNotNull(signercert);

        byte[] sodBytes = res.getProcessedData();
        SODFile sod = new SODFile(new ByteArrayInputStream(sodBytes));
        boolean verify = sod.checkDocSignature(signercert);
        assertTrue("Signature verification", verify);

        // Check the SOD
        Map<Integer, byte[]> actualDataGroupHashes = sod.getDataGroupHashes();
        assertEquals(expectedHashes.size(), actualDataGroupHashes.size());
        for(Map.Entry<Integer, byte[]> entry : actualDataGroupHashes.entrySet()) {
            assertTrue("DG"+entry.getKey(), Arrays.equals(expectedHashes.get(entry.getKey()), entry.getValue()));
        }
        assertEquals(digestAlg, sod.getDigestAlgorithm());
        assertEquals(sigAlg, sod.getDigestEncryptionAlgorithm());
        return sod;
    }

    private byte[] digestHelper(byte[] data, String digestAlgorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(digestAlgorithm);
        return md.digest(data);
    }

    private void setupWorkers() {

        final GlobalConfigurationSessionMock globalMock
                = new GlobalConfigurationSessionMock();
        final WorkerSessionMock workerMock = new WorkerSessionMock(globalMock);
        globalConfig = globalMock;
        workerSession = workerMock;



        // WORKER1
        {
            final int workerId = WORKER1;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner1");
            config.setProperty(KEYSTOREPATH, keystore1.getAbsolutePath());
            config.setProperty(KEYSTOREPASSWORD, keystore1Password);
            config.setProperty(AUTHTYPE, "NOAUTH");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER2 - Worker7898: SHA512, default hashing setting
        {
            final int workerId = WORKER2;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner2");
            config.setProperty(KEYSTOREPATH, keystore1.getAbsolutePath());
            config.setProperty(KEYSTOREPASSWORD, keystore1Password);
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA512");
            config.setProperty("SIGNATUREALGORITHM", "SHA512withRSA");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER3 - Worker7899: Default algorithms, DODATAGROUPHASHING=true
        {
            final int workerId = WORKER3;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner1");
            config.setProperty(KEYSTOREPATH, keystore1.getAbsolutePath());
            config.setProperty(KEYSTOREPASSWORD, keystore1Password);
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DODATAGROUPHASHING", "true");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER4 - Worker7900: SHA512, DODATAGROUPHASHING=true
        {
            final int workerId = WORKER4;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner1");
            config.setProperty(KEYSTOREPATH, keystore1.getAbsolutePath());
            config.setProperty(KEYSTOREPASSWORD, keystore1Password);
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA512");
            config.setProperty("SIGNATUREALGORITHM", "SHA512withRSA");
            config.setProperty("DODATAGROUPHASHING", "true");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER5 - With LDS version 1.8
        {
            final int workerId = WORKER5;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner5");
            config.setProperty(KEYSTOREPATH, keystore1.getAbsolutePath());
            config.setProperty(KEYSTOREPASSWORD, keystore1Password);
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("LDSVERSION", "0108");
            config.setProperty("UNICODEVERSION", "040000");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER11
        {
            final int workerId = WORKER11;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner11");
            config.setProperty(KEYSTOREPATH, keystore1.getAbsolutePath());
            config.setProperty(KEYSTOREPASSWORD, keystore1Password);
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA1");
            config.setProperty("SIGNATUREALGORITHM", "SHA1withRSAandMGF1");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER12
        {
            final int workerId = WORKER12;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner12");
            config.setProperty(KEYSTOREPATH, keystore1.getAbsolutePath());
            config.setProperty(KEYSTOREPASSWORD, keystore1Password);
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA256");
            config.setProperty("SIGNATUREALGORITHM", "SHA256withRSAandMGF1");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER13
        {
            final int workerId = WORKER13;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner13");
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty(KEYSTOREPATH, keystore1.getAbsolutePath());
            config.setProperty(KEYSTOREPASSWORD, keystore1Password);
            config.setProperty("DIGESTALGORITHM", "SHA384");
            config.setProperty("SIGNATUREALGORITHM", "SHA384withRSAandMGF1");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER14
        {
            final int workerId = WORKER14;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner14");
            config.setProperty(KEYSTOREPATH, keystore1.getAbsolutePath());
            config.setProperty(KEYSTOREPASSWORD, keystore1Password);
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA512");
            config.setProperty("SIGNATUREALGORITHM", "SHA512withRSAandMGF1");
            config.setProperty("defaultKey", HardCodedCryptoTokenAliases.KEY_ALIAS_2); // Use a larger key
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER15
        {
            final int workerId = WORKER15;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner15");
            config.setProperty(KEYSTOREPATH, keystore1.getAbsolutePath());
            config.setProperty(KEYSTOREPASSWORD, keystore1Password);
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA1");
            config.setProperty("SIGNATUREALGORITHM", "SHA256withRSAandMGF1");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER16 - The other DN order
        {
            final int workerId = WORKER16;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner16");
            config.setProperty(KEYSTOREPATH, keystore2.getAbsolutePath());
            config.setProperty(KEYSTOREPASSWORD, keystore2Password);
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA1");
            config.setProperty("SIGNATUREALGORITHM", "SHA1withRSAandMGF1");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }

        // WORKER17 - CA and signer using SHA256withRSAandMGF1
        {
            final int workerId = WORKER17;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner17");
            config.setProperty(KEYSTOREPATH, keystore3.getAbsolutePath());
            config.setProperty(KEYSTOREPASSWORD, keystore3Password);
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA256");
            config.setProperty("SIGNATUREALGORITHM", "SHA256withRSAandMGF1");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }
        
        // WORKER16 ECDSA
        {
            final int workerId = WORKER18;
            final WorkerConfig config = new WorkerConfig();
            config.setProperty(NAME, "TestMRTDSODSigner16");
            config.setProperty(KEYSTOREPATH, keystore4.getAbsolutePath());
            config.setProperty(KEYSTOREPASSWORD, keystore4Password);
            config.setProperty(AUTHTYPE, "NOAUTH");
            config.setProperty("DIGESTALGORITHM", "SHA256");
            config.setProperty("SIGNATUREALGORITHM", "SHA256withECDSA");
            workerMock.setupWorker(workerId, CRYPTOTOKEN_CLASSNAME, config,
                    new MRTDSODSigner() {
                @Override
                protected IGlobalConfigurationSession.IRemote
                        getGlobalConfigurationSession() {
                    return globalConfig;
                }
            });
            workerSession.reloadConfiguration(workerId);
        }
        
    }
}
