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
package org.signserver.server.cryptotokens;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.security.auth.x500.X500Principal;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.fail;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.util.CertTools;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.KeyTestResult;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.TokenOutOfSpaceException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Test signing with all signers using a PKCS11CryptoToken.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class P11SignTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(P11SignTest.class);

    private static final int CRYPTO_TOKEN = 20100;
    private static final int WORKER_PDF = 20000;
    private static final int WORKER_TSA = 20001;
    private static final int WORKER_SOD = 20002;
    private static final int WORKER_CMS = 20003;
    private static final int WORKER_XML = 20004;
    private static final int WORKER_XML2 = 20014;
    private static final int WORKER_ODF = 20005;
    private static final int WORKER_OOXML = 20006;
    private static final int WORKER_MSA = 20007;
    private static final int WORKER_TSA_ALTKEY = 20008;
    private static final int WORKER_PLAIN = 20020;

    private static final String MSAUTHCODE_REQUEST_DATA =
    		"MIIBIwYKKwYBBAGCNwMCATCCARMGCSqGSIb3DQEHAaCCAQQEggEAVVSpOKf9zJYc" +
    		"tyvqgeHfO9JkobPYihUZcW9TbYzAUiJGEsElNCnLUaO0+MZG0TS7hlzqKKvrdXc7" +
    		"O/8C7c8YyjYF5YrLiaYS8cw3VbaQ2M1NWsLGzxF1pxsR9sMDJvfrryPaWj4eTi3Y" +
    		"UqRNS+GTa4quX4xbmB0KqMpCtrvuk4S9cgaJGwxmSE7N3omzvERTUxp7nVSHtms5" +
    		"lVMb082JFlABT1/o2mL5O6qFG119JeuS1+ZiL1AEy//gRs556OE1TB9UEQU2bFUm" +
    		"zBD4VHvkOOB/7X944v9lmK5y9sFv+vnf/34catL1A+ZNLwtd1Qq2VirqJxRK/T61" +
    		"QoSWj4rGpw==";

    private static final String TEST_KEY_ALIAS = "p11testkey1234";
    private static final String TEST_KEY_ALIAS_2 = "somekey123";
    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenP11";

    private final String sharedLibraryName;
    private final String sharedLibraryPath;
    private final String slot;
    private final String pin;
    private final String existingKey1;

    private final File pdfSampleFile;
    private final File odfSampleFile;
    private final File ooxmlSampleFile;

    private final ModulesTestCase testCase = new ModulesTestCase();

    private final WorkerSession workerSession = testCase.getWorkerSession();
    private final ProcessSessionRemote processSession = testCase.getProcessSession();
    private final GlobalConfigurationSessionRemote globalSession = testCase.getGlobalSession();

    public P11SignTest() throws FileNotFoundException {
        final File home = PathUtil.getAppHome();
        pdfSampleFile = new File(home, "res/test/pdf/sample.pdf");
        odfSampleFile = new File(home, "res/test/test.odt");
        ooxmlSampleFile = new File(home, "res/test/test.docx");
        sharedLibraryName = testCase.getConfig().getProperty("test.p11.sharedLibraryName");
        sharedLibraryPath = testCase.getConfig().getProperty("test.p11.sharedLibraryPath");
        slot = testCase.getConfig().getProperty("test.p11.slot");
        pin = testCase.getConfig().getProperty("test.p11.pin");
        existingKey1 = testCase.getConfig().getProperty("test.p11.existingkey1");
    }

    @Before
    public void setUp() {
        Assume.assumeFalse("P11NG".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.provider")));
        SignServerUtil.installBCProvider();
    }

    private void setupCryptoTokenProperties(final int tokenId, final boolean cache) {
        // Setup token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(tokenId, "SLOT", slot);
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1); // Test key
        workerSession.setWorkerProperty(tokenId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    private void setPDFSignerOnlyProperties() {
        // Setup worker
        workerSession.setWorkerProperty(WORKER_PDF, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(WORKER_PDF, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.pdfsigner.PDFSigner");
        workerSession.setWorkerProperty(WORKER_PDF, "NAME", "PDFSignerP11");
        workerSession.setWorkerProperty(WORKER_PDF, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(WORKER_PDF, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(WORKER_PDF, "DEFAULTKEY", existingKey1);
    }

    private void setPDFSignerWithCryptoProperties(final boolean cache) {
        // Setup worker
        workerSession.setWorkerProperty(WORKER_PDF, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(WORKER_PDF, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.pdfsigner.PDFSigner");
        workerSession.setWorkerProperty(WORKER_PDF, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(WORKER_PDF, "NAME", "PDFSignerP11");
        workerSession.setWorkerProperty(WORKER_PDF, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(WORKER_PDF, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(WORKER_PDF, "SLOT", slot);
        workerSession.setWorkerProperty(WORKER_PDF, "PIN", pin);
        workerSession.setWorkerProperty(WORKER_PDF, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(WORKER_PDF, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    /** Tests that the getCertificateRequest method generates a request. */
    @Test
    public void testGenerateCSR() throws Exception {
        try {
            setPDFSignerWithCryptoProperties(false);
            workerSession.reloadConfiguration(WORKER_PDF);

            // Tests generating a CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
            AbstractCertReqData csr = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
            assertNotNull(csr);
            assertNotNull(csr.toBinaryForm());
            assertTrue(csr.toBinaryForm().length > 0);

            // Test for an non-existing key label
            setPDFSignerWithCryptoProperties(false);
            workerSession.setWorkerProperty(WORKER_PDF, "DEFAULTKEY", "NON-EXISTING-KEY-LABEL");
            workerSession.reloadConfiguration(WORKER_PDF);
            try {
                certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
                workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
                fail("Should have thrown exception as the DEFAULTKEY does not exist");
            } catch (CryptoTokenOfflineException ok) { // NOPMD
                // OK
            }
        } finally {
            testCase.removeWorker(WORKER_PDF);
        }
    }

    /** Tests that the getCertificateRequest method generates a request. */
    @Test
    public void testGenerateCSR_separateToken() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            setPDFSignerOnlyProperties();
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(WORKER_PDF);

            // Tests generating a CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
            AbstractCertReqData csr = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
            assertNotNull(csr);
            assertNotNull(csr.toBinaryForm());
            assertTrue(csr.toBinaryForm().length > 0);

            // Test for an non-existing key label
            workerSession.setWorkerProperty(WORKER_PDF, "DEFAULTKEY", "NON-EXISTING-KEY-LABEL");
            workerSession.reloadConfiguration(WORKER_PDF);
            try {
                certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
                workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
                fail("Should have thrown exception as the DEFAULTKEY does not exist");
            } catch (CryptoTokenOfflineException ok) { // NOPMD
                // OK
            }
        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
            testCase.removeWorker(WORKER_PDF);
        }
    }

    // Input should be 20 byte hashed data for successful signing with NONEwithDSA (signing only works with SHA-1 hashed data as of now)
    @Test
    public void testPlainSigner_NONEwithDSA() throws Exception {
        final int workerId = WORKER_PLAIN;
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            setPlainSignerProperties();
            workerSession.reloadConfiguration(workerId);

            plainSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }
    
    @Test
    public void testPlainSigner_NONEwithECDSA() throws Exception {
        final int workerId = WORKER_PLAIN;
        String key = "testKeyEc";
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            setPlainSignerProperties();
            workerSession.reloadConfiguration(workerId);

            workerSession.generateSignerKey(new WorkerIdentifier(20020), "ECDSA", "secp256r1", key, pin.toCharArray());
            workerSession.setWorkerProperty(20020, "DEFAULTKEY", key);
            workerSession.setWorkerProperty(20020, "SIGNATUREALGORITHM", "NONEwithECDSA");
            workerSession.reloadConfiguration(20020);

            // Generate CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA256withECDSA", "CN=Worker" + 20020, null);
            AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(20020), certReqInfo, false);

            // Issue certificate
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
            KeyPair issuerKeyPair = CryptoUtils.generateEcCurve("secp256r1");
            X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

            // Install certificate and chain
            workerSession.uploadSignerCertificate(20020, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(20020, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(20020);

            X509Certificate xcert = CertTools.getCertfromByteArray(cert.getEncoded(), X509Certificate.class);

            // Test active
            List<String> errors = workerSession.getStatus(new WorkerIdentifier(20020)).getFatalErrors();
            assertEquals("errors: " + errors, 0, errors.size());

            byte[] plainText = "some-data".getBytes(StandardCharsets.US_ASCII);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(plainText);
            byte[] hash = md.digest();

            // Test signing
            GenericSignResponse response = testCase.signGenericDocument(20020, hash);

            byte[] signatureBytes = response.getProcessedData();

            assertTrue("signature verification", verifySignature(plainText, signatureBytes, "SHA256withECDSA", xcert.getPublicKey(), "BC"));
        } finally {
            workerSession.removeKey(new WorkerIdentifier(20020), key);
            testCase.removeWorker(workerId);
        }
    }

    private void setPlainSignerProperties() {
        // Setup worker
        workerSession.setWorkerProperty(20020, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(20020, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.PlainSigner");
        workerSession.setWorkerProperty(20020, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(20020, "NAME", "PlainSignerP11");
        workerSession.setWorkerProperty(20020, "AUTHTYPE", "NOAUTH");
    }

    private void plainSigner() throws Exception {
        String key = "testKey";

        try {
            workerSession.generateSignerKey(new WorkerIdentifier(20020), "DSA", "1024", key, pin.toCharArray());
            workerSession.setWorkerProperty(20020, "DEFAULTKEY", key);
            workerSession.setWorkerProperty(20020, "SIGNATUREALGORITHM", "NONEwithDSA");
            workerSession.reloadConfiguration(20020);

            // Generate CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithDSA", "CN=Worker" + 20020, null);
            AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(20020), certReqInfo, false);

            // Issue certificate
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
            KeyPair issuerKeyPair = CryptoUtils.generateDSA(1024);
            X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA1withDSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

            // Install certificate and chain
            workerSession.uploadSignerCertificate(20020, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(20020, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(20020);

            // Test active
            List<String> errors = workerSession.getStatus(new WorkerIdentifier(20020)).getFatalErrors();
            assertEquals("errors: " + errors, 0, errors.size());

            byte[] plainText = "some-data".getBytes(StandardCharsets.US_ASCII);
            MessageDigest md = MessageDigest.getInstance("SHA-1"); // 20 byte length of hashed data
            md.update(plainText);
            byte[] hash = md.digest();

            // Test signing
            testCase.signGenericDocument(20020, hash);
        } finally {
            workerSession.removeKey(new WorkerIdentifier(20020), key);
        }
    }

    @Test
    public void testPlainSigner_SHA256withRSAandMGF1() throws Exception {
        Assume.assumeTrue("Test requires HSM that supports RSASSA-PSS", "true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.PSS_SIGNATURE_ALGORITHM_SUPPORTED")));
        final int workerId = WORKER_PLAIN;
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            setPlainSignerProperties();
            workerSession.setWorkerProperty(20020, "DEFAULTKEY", existingKey1);
            workerSession.setWorkerProperty(20020, "SIGNATUREALGORITHM", "SHA256withRSAandMGF1");
            workerSession.reloadConfiguration(20020);

            // Generate CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA256WithRSAandMGF1", "CN=Worker" + 20020, null);
            AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(20020), certReqInfo, false);

            // Issue certificate
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
            KeyPair issuerKeyPair = CryptoUtils.generateRSA(1024);
            X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256withRSAandMGF1").setProvider("BC").build(issuerKeyPair.getPrivate()));

            // Install certificate and chain
            workerSession.uploadSignerCertificate(20020, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(20020, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(20020);

            X509Certificate xcert = CertTools.getCertfromByteArray(cert.getEncoded(), X509Certificate.class);

            // Test active
            List<String> errors = workerSession.getStatus(new WorkerIdentifier(20020)).getFatalErrors();
            assertEquals("errors: " + errors, 0, errors.size());

            byte[] plainText = "some-data".getBytes(StandardCharsets.US_ASCII);

            // Test signing
            GenericSignResponse response = testCase.signGenericDocument(20020, plainText);
            byte[] signatureBytes = response.getProcessedData();

            assertTrue("signature verification", verifySignature(plainText, signatureBytes, "SHA256withRSAandMGF1", xcert.getPublicKey(), "BC"));
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    public static boolean verifySignature(final byte[] plainText, final byte[] signatureBytes, final String sigAlgName, final PublicKey publicKey, final String provider) throws Exception {
        final boolean result;
        Signature signature = Signature.getInstance(sigAlgName, provider);
        signature.initVerify(publicKey);
        signature.update(plainText);
        result = signature.verify(signatureBytes);
        return result;
    }

    /**
     * Tests setting up a PDF Signer, giving it a certificate and sign a document.
     */
    @Test
    public void testPDFSigner_uncached() throws Exception {
        try {
            setPDFSignerWithCryptoProperties(false);
            workerSession.reloadConfiguration(WORKER_PDF);

            pdfSignerTest();
        } finally {
            testCase.removeWorker(WORKER_PDF);
        }
    }

    /**
     * Tests setting up a PDF Signer, giving it a certificate and sign a document.
     */
    @Test
    public void testPDFSigner_uncached_separateToken() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            setPDFSignerOnlyProperties();
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(WORKER_PDF);

            pdfSignerTest();
        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
            testCase.removeWorker(WORKER_PDF);
        }
    }

    /**
     * Tests setting up a PDF Signer, giving it a certificate and sign a document.
     */
    @Test
    public void testPDFSigner_cached() throws Exception {
        try {
            setPDFSignerWithCryptoProperties(true);
            workerSession.reloadConfiguration(WORKER_PDF);

            pdfSignerTest();
        } finally {
            testCase.removeWorker(WORKER_PDF);
        }
    }

    /**
     * Tests setting up a PDF Signer, giving it a certificate and sign a document.
     */
    @Test
    public void testPDFSigner_cached_separateToken() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, true);
            setPDFSignerOnlyProperties();
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(WORKER_PDF);

            pdfSignerTest();
        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
            testCase.removeWorker(WORKER_PDF);
        }
    }

    private void pdfSignerTest() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
        AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(WORKER_PDF, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(WORKER_PDF, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(WORKER_PDF);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(WORKER_PDF)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        testCase.signGenericDocument(WORKER_PDF, readFile(pdfSampleFile));
    }

    private byte[] readFile(File file) throws IOException {
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(
                file));
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            bout.write(b);
        }
        return bout.toByteArray();
    }

    private void setTimeStampSignerProperties(final boolean cache) throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(WORKER_TSA, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(WORKER_TSA, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.tsa.TimeStampSigner");
        workerSession.setWorkerProperty(WORKER_TSA, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(WORKER_TSA, "NAME", "TSSignerP11");
        workerSession.setWorkerProperty(WORKER_TSA, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(WORKER_TSA, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(WORKER_TSA, "SLOT", slot);
        workerSession.setWorkerProperty(WORKER_TSA, "PIN", pin);
        workerSession.setWorkerProperty(WORKER_TSA, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(WORKER_TSA, "DEFAULTTSAPOLICYOID", "1.2.3");
        workerSession.setWorkerProperty(WORKER_TSA, "CACHE_PRIVATEKEY", String.valueOf(cache));
        workerSession.setWorkerProperty(WORKER_TSA, "ACCEPTANYPOLICY", "true");

        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_TSA, null);
        AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_TSA), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo())
                .addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping).toASN1Primitive())
                .build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(WORKER_TSA, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(WORKER_TSA, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(WORKER_TSA);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(WORKER_TSA)).getFatalErrors();
        if (!errors.isEmpty()) {
            throw new Exception("Failed to configure TimeStampSigner: " + errors);
        }
    }

    /**
     * Test that key usage counter increments as expected for TimeStampSigner
     * then the certificate is uploaded to the signer configuration.
     */
    @Test
    public void testTSSigner_keyUsageCounterCertInConfig() throws Exception {
        testTSSigner_keyUsageCounter(true);
    }

    /**
     * Test that key usage counter increments as expected for TimeStampSigner
     * then the certificate is uploaded to the token.
     */
    @Test
    public void testTSSigner_keyUsageCounterCertInToken() throws Exception {
        testTSSigner_keyUsageCounter(false);
    }

    private void testTSSigner_keyUsageCounter(final boolean certInConfig)
        throws Exception {
        final String key = "altkey";
        try {
            // Setup worker
            workerSession.setWorkerProperty(WORKER_TSA_ALTKEY, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
            workerSession.setWorkerProperty(WORKER_TSA_ALTKEY, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.tsa.TimeStampSigner");
            workerSession.setWorkerProperty(WORKER_TSA_ALTKEY, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
            workerSession.setWorkerProperty(WORKER_TSA_ALTKEY, "NAME", "TSSignerAltKey");
            workerSession.setWorkerProperty(WORKER_TSA_ALTKEY, "AUTHTYPE", "NOAUTH");
            workerSession.setWorkerProperty(WORKER_TSA_ALTKEY, "SHAREDLIBRARYNAME", sharedLibraryName);
            workerSession.setWorkerProperty(WORKER_TSA_ALTKEY, "SLOT", slot);
            workerSession.setWorkerProperty(WORKER_TSA_ALTKEY, "PIN", pin);
            workerSession.setWorkerProperty(WORKER_TSA_ALTKEY, "DEFAULTKEY", key);
            workerSession.setWorkerProperty(WORKER_TSA_ALTKEY, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(WORKER_TSA_ALTKEY, "ACCEPTANYPOLICY", "true");

            workerSession.generateSignerKey(new WorkerIdentifier(WORKER_TSA_ALTKEY),
                                            "RSA", "2048", key, pin.toCharArray());

            // Generate CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_TSA_ALTKEY, null);
            AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_TSA_ALTKEY), certReqInfo, false);

            // Issue certificate
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
            KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
            X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo())
                    .addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping).toASN1Primitive())
                    .build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

            // Install certificate and chain
            if (certInConfig) {
                workerSession.uploadSignerCertificate(WORKER_TSA_ALTKEY, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
                workerSession.uploadSignerCertificateChain(WORKER_TSA_ALTKEY, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            } else {
                workerSession.importCertificateChain(new WorkerIdentifier(WORKER_TSA_ALTKEY),
                        Collections.singletonList(cert.getEncoded()),
                                                     key, pin.toCharArray());
            }
            workerSession.reloadConfiguration(WORKER_TSA_ALTKEY);

            final long keyUsageBefore = workerSession.getKeyUsageCounterValue(new WorkerIdentifier(WORKER_TSA_ALTKEY));

            // Test signing
            TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
            byte[] requestBytes = timeStampRequest.getEncoded();
            GenericSignRequest signRequest = new GenericSignRequest(567, requestBytes);
            final GenericSignResponse res = (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_TSA_ALTKEY), signRequest, new RemoteRequestContext());
            Certificate signercert = res.getSignerCertificate();
            assertNotNull(signercert);
            final TimeStampResponse timeStampResponse = new TimeStampResponse(res.getProcessedData());
            timeStampResponse.validate(timeStampRequest);

            assertEquals("Token granted", PKIStatus.GRANTED, timeStampResponse.getStatus());
            assertNotNull("Got timestamp token", timeStampResponse.getTimeStampToken());

            assertEquals("Key used once", keyUsageBefore + 1, workerSession.getKeyUsageCounterValue(new WorkerIdentifier(WORKER_TSA_ALTKEY)));

        } finally {
            workerSession.removeKey(new WorkerIdentifier(WORKER_TSA_ALTKEY), key);
            testCase.removeWorker(WORKER_TSA_ALTKEY);
        }
    }


    /**
     * Tests setting up a TimeStamp Signer, giving it a certificate and request a time-stamp token.
     */
    @Test
    public void testTSSigner_uncached() throws Exception {
        try {
            setTimeStampSignerProperties(false);
            workerSession.reloadConfiguration(WORKER_TSA);
            tsSigner();
        } finally {
            testCase.removeWorker(WORKER_TSA);
        }
    }

    @Test
    public void testTSSigner_cached() throws Exception {
        try {
            setTimeStampSignerProperties(true);
            workerSession.reloadConfiguration(WORKER_TSA);
            tsSigner();
        } finally {
            testCase.removeWorker(WORKER_TSA);
        }
    }

    private void tsSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_TSA, null);
        AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_TSA), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(WORKER_TSA, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(WORKER_TSA, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(WORKER_TSA);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(WORKER_TSA)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA256, new byte[32], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest = new GenericSignRequest(567, requestBytes);
        final GenericSignResponse res = (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_TSA), signRequest, new RemoteRequestContext());
        Certificate signercert = res.getSignerCertificate();
        assertNotNull(signercert);
        final TimeStampResponse timeStampResponse = new TimeStampResponse(res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        assertEquals("Token granted", PKIStatus.GRANTED, timeStampResponse.getStatus());
        assertNotNull("Got timestamp token", timeStampResponse.getTimeStampToken());
    }

    private void setMRTDSODSignerProperties(final boolean cache) {
        // Setup worker
        workerSession.setWorkerProperty(20002, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(20002, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.mrtdsodsigner.MRTDSODSigner");
        workerSession.setWorkerProperty(20002, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(20002, "NAME", "SODSignerP11");
        workerSession.setWorkerProperty(20002, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(20002, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(20002, "SLOT", slot);
        workerSession.setWorkerProperty(20002, "PIN", pin);
        workerSession.setWorkerProperty(20002, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(20002, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    /**
     * Tests setting up a MRTD SOD Signer, giving it a certificate and requests an SOd.
     */
    @Test
    public void testMRTDSODSigner_uncached() throws Exception {
        final int workerId = WORKER_SOD;
        try {
            setMRTDSODSignerProperties(false);
            workerSession.reloadConfiguration(workerId);

            mrtdsodSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    @Test
    public void testMRTDSODSigner_cached() throws Exception {
        final int workerId = WORKER_SOD;
        try {
            setMRTDSODSignerProperties(true);
            workerSession.reloadConfiguration(workerId);

            mrtdsodSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void mrtdsodSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + 20002, null);
        AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(20002), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder issuerCert = new JcaX509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), new X500Name("CN=TestP11 Issuer"), issuerKeyPair.getPublic()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(20002, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(20002, Arrays.asList(cert.getEncoded(), issuerCert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(20002);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(20002)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        HashMap<Integer, byte[]> dgs = new HashMap<>();
        dgs.put(1, Base64.decode("PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=".getBytes(StandardCharsets.US_ASCII)));
        dgs.put(2, Base64.decode("PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=".getBytes(StandardCharsets.US_ASCII)));
        dgs.put(3, Base64.decode("PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=".getBytes(StandardCharsets.US_ASCII)));
        final SODSignRequest signRequest = new SODSignRequest(233, dgs);
        final SODSignResponse res = (SODSignResponse) processSession.process(new WorkerIdentifier(20002), signRequest, new RemoteRequestContext());
        Certificate signercert = res.getSignerCertificate();
        assertNotNull(signercert);
    }

    private void setCMSSignerProperties(final int workerId, final boolean cached) {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.CMSSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "CMSSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOT", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cached));
    }

    /**
     * Tests setting up a CMS Signer, giving it a certificate and sign a file.
     */
    @Test
    public void testCMSSigner_uncached() throws Exception {
        final int workerId = WORKER_CMS;
        try {
            setCMSSignerProperties(workerId, false);
            workerSession.reloadConfiguration(workerId);

            cmsSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    @Test
    public void testCMSSigner_cached() throws Exception {
        final int workerId = WORKER_CMS;
        try {
            setCMSSignerProperties(workerId, true);
            workerSession.reloadConfiguration(workerId);

            cmsSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void cmsSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + 20003, null);
        AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(20003), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(20003, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(20003, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(20003);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(20003)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        cmsSignAndAssertOk(20003, "Sample data".getBytes(), workerSession.getSignerCertificate(new WorkerIdentifier(20003)));
    }

    private void cmsSigner_existingCertInToken() throws Exception {

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(20003)).getFatalErrors();

        if (!errors.isEmpty()) {
            throw new Exception("This test assumes the existing key " + existingKey1 + " to have a certificate: " + errors);
        }

        // Test signing
        cmsSignAndAssertOk(20003, "Sample data".getBytes(), workerSession.getSignerCertificate(new WorkerIdentifier(20003)));
    }

    /**
     * Tests setting up a CMS Signer, not giving it any certificate.
     * Note: This test expects the existing key to have a proper certificate.
     */
    @Test
    public void testCMSSigner_existingCertInToken() throws Exception {
        final int workerId = WORKER_CMS;
        try {
            setCMSSignerProperties(workerId, false);
            workerSession.reloadConfiguration(workerId);

            cmsSigner_existingCertInToken();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void cmsSignAndAssertOk(int workerId, byte[] data, Certificate expectedSignerCert) throws Exception {
        GenericSignResponse resp = testCase.signGenericDocument(workerId, data);

        CMSSignedData s = new CMSSignedData(resp.getProcessedData());

        int verified = 0;
        Store certStore = s.getCertificates();
        SignerInformationStore signers = s.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();
        X509CertificateHolder signerCert = null;

        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            Collection certCollection = certStore.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            signerCert = (X509CertificateHolder) certIt.next();

            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerCert))) {
                verified++;
            }
        }

        assertEquals("signer verified", 1, verified);
        if (signerCert != null) {
            assertEquals("Same certificate", Hex.toHexString(expectedSignerCert.getEncoded()), Hex.toHexString(signerCert.getEncoded()));
        } else {
            fail("No certificate");
        }

    }


    private void setXMLSignerProperties(final boolean cache) {
        // Setup worker
        workerSession.setWorkerProperty(20004, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(20004, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.xmlsigner.XMLSigner");
        workerSession.setWorkerProperty(20004, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(20004, "NAME", "XMLSignerP11");
        workerSession.setWorkerProperty(20004, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(20004, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(20004, "SLOT", slot);
        workerSession.setWorkerProperty(20004, "PIN", pin);
        workerSession.setWorkerProperty(20004, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(20004, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    private void setXMLSignerPropertiesReferingToken() {
        // Setup worker
        workerSession.setWorkerProperty(20014, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(20014, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.xmlsigner.XMLSigner");
        workerSession.setWorkerProperty(20014, "NAME", "XMLSignerRefering");
        workerSession.setWorkerProperty(20014, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(20014, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(20014, "CACHE_PRIVATEKEY", String.valueOf(true));
        workerSession.setWorkerProperty(20014, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
    }

    /**
     * Tests setting up a XML Signer, giving it a certificate and sign a document.
     */
    @Test
    public void testXMLSigner_uncached() throws Exception {
        final int workerId = WORKER_XML;
        try {
            setXMLSignerProperties(false);
            workerSession.reloadConfiguration(workerId);

            xmlSigner(workerId);
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    @Test
    public void testXMLSigner_cached() throws Exception {
        final int workerId = WORKER_XML;
        try {
            setXMLSignerProperties(true);
            workerSession.reloadConfiguration(workerId);

            xmlSigner(workerId);
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Exercises a signer using a separate token and where the private key is
     * cached (in the worker).
     */
    @Test
    public void testXMLSigner_cached_separateToken() throws Exception {
        final int workerId = WORKER_XML2;
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setXMLSignerPropertiesReferingToken();
            workerSession.reloadConfiguration(workerId);

            xmlSigner(workerId);
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void xmlSigner(final int workerId) throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(workerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(workerId, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(workerId);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        testCase.signGenericDocument(workerId, "<sampledata/>".getBytes());

        // Test removing the DEFAULTKEY property, should result in a CryptoTokenOfflineException
        workerSession.removeWorkerProperty(workerId, "DEFAULTKEY");
        workerSession.reloadConfiguration(workerId);

        try {
            testCase.signGenericDocument(workerId, "<sampledata/>".getBytes());
            fail("Should throw a CryptoTokenOfflineException");
        } catch (CryptoTokenOfflineException e) {
            // expected
        }
    }

    private void setODFSignerProperties(final boolean cache) {
        // Setup worker
        workerSession.setWorkerProperty(20005, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(20005, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.odfsigner.ODFSigner");
        workerSession.setWorkerProperty(20005, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(20005, "NAME", "ODFSignerP11");
        workerSession.setWorkerProperty(20005, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(20005, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(20005, "SLOT", slot);
        workerSession.setWorkerProperty(20005, "PIN", pin);
        workerSession.setWorkerProperty(20005, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(20005, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    /**
     * Tests setting up a ODF Signer, giving it a certificate and sign a document.
     */
    @Test
    public void testODFSigner_uncached() throws Exception {
        final int workerId = WORKER_ODF;
        try {
            setODFSignerProperties(false);
            workerSession.reloadConfiguration(workerId);

            odfSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    @Test
    public void testODFSigner_cached() throws Exception {
        final int workerId = WORKER_ODF;
        try {
            setODFSignerProperties(true);
            workerSession.reloadConfiguration(workerId);

            odfSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void odfSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + 20005, null);
        AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(20005), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(20005, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(20005, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(20005);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(20005)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        testCase.signGenericDocument(20005, readFile(odfSampleFile));
    }

    private void setOOXMLSignerProperties(final boolean cache) {
        // Setup worker
        workerSession.setWorkerProperty(20006, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(20006, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.ooxmlsigner.OOXMLSigner");
        workerSession.setWorkerProperty(20006, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(20006, "NAME", "OOXMLSignerP11");
        workerSession.setWorkerProperty(20006, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(20006, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(20006, "SLOT", slot);
        workerSession.setWorkerProperty(20006, "PIN", pin);
        workerSession.setWorkerProperty(20006, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(20006, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    /**
     * Tests setting up a OOXML Signer, giving it a certificate and sign a document.
     */
    @Test
    public void testOOXMLSigner_uncached() throws Exception {
        final int workerId = WORKER_OOXML;
        try {
            setOOXMLSignerProperties(false);
            workerSession.reloadConfiguration(workerId);
            ooxmlSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    @Test
    public void testOOXMLSigner_cached() throws Exception {
        final int workerId = WORKER_OOXML;
        try {
            setOOXMLSignerProperties(true);
            workerSession.reloadConfiguration(workerId);
            ooxmlSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void ooxmlSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + 20006, null);
        AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(20006), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(20006, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(20006, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(20006);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(20006)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        testCase.signGenericDocument(20006, readFile(ooxmlSampleFile));
    }

    private void setMSAuthTimeStampSignerProperties(final boolean cache) {
        // Setup worker
        workerSession.setWorkerProperty(20007, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(20007, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.tsa.MSAuthCodeTimeStampSigner");
        workerSession.setWorkerProperty(20007, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(20007, "NAME", "MSAuthTSSignerP11");
        workerSession.setWorkerProperty(20007, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(20007, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(20007, "SLOT", slot);
        workerSession.setWorkerProperty(20007, "PIN", pin);
        workerSession.setWorkerProperty(20007, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(20007, "DEFAULTTSAPOLICYOID", "1.2.3");
        workerSession.setWorkerProperty(20007, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    /**
     * Tests setting up a MSAuthCodeTimeStamp Signer, giving it a certificate and request a time-stamp token.
     */
    @Test
    public void testMSAuthTSSigner_uncached() throws Exception {
        final int workerId = WORKER_MSA;
        try {
            setMSAuthTimeStampSignerProperties(false);
            workerSession.reloadConfiguration(workerId);
            msAuthTSSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    @Test
    public void testMSAuthTSSigner_cached() throws Exception {
        final int workerId = WORKER_MSA;
        try {
            setMSAuthTimeStampSignerProperties(true);
            workerSession.reloadConfiguration(workerId);
            msAuthTSSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void msAuthTSSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + 20007, null);
        AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(20007), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(20007, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(20007, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(20007);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(20007)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        GenericSignRequest signRequest = new GenericSignRequest(678, MSAUTHCODE_REQUEST_DATA.getBytes());
        final GenericSignResponse res = (GenericSignResponse) processSession.process(new WorkerIdentifier(20007), signRequest, new RemoteRequestContext());
        Certificate signercert = res.getSignerCertificate();
        assertNotNull(signercert);

        byte[] buf = res.getProcessedData();
        CMSSignedData s = new CMSSignedData(Base64.decode(buf));

        int verified = 0;
        Store certStore = s.getCertificates();
        SignerInformationStore signers = s.getSignerInfos();
        Collection<SignerInformation> signerInfos = signers.getSigners();

        for (SignerInformation si : signerInfos) {
            Collection certCollection = certStore.getMatches(si.getSID());
            X509CertificateHolder signerCert = (X509CertificateHolder) certCollection.stream().findFirst().orElse(null);
            if (si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerCert))) {
                verified++;
            }
        }

        assertEquals("signer verified", 1, verified);
    }

    /**
     * Test having default PKCS11CryptoToken properties.
     * Tests setting up a CMS Signer, giving it a certificate and sign a file.
     */
    @Test
    public void testDefaultGlobalProperties() throws Exception {
        final int workerId = WORKER_CMS;
        try {
            // Setup worker
            workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
            workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.CMSSigner");
            workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "DEFAULT.SHAREDLIBRARYNAME", sharedLibraryName);
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "DEFAULT.SLOT", slot);
            workerSession.setWorkerProperty(workerId, "NAME", "CMSSignerP11");
            workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
            workerSession.setWorkerProperty(workerId, "PIN", pin);
            workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
            workerSession.reloadConfiguration(workerId);

            cmsSigner();
        } finally {
            testCase.removeWorker(workerId);
            globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "DEFAULT.SHAREDLIBRARY");
            globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "DEFAULT.SHAREDLIBRARYNAME");
            globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "DEFAULT.SLOT");
        }
    }

    private Set<String> getKeyAliases(final int workerId) throws Exception {
        Collection<KeyTestResult> testResults = workerSession.testKey(new WorkerIdentifier(workerId), "all", pin.toCharArray());
        final HashSet<String> results = new HashSet<>();
        for (KeyTestResult testResult : testResults) {
            results.add(testResult.getAlias());
        }
        return results;
    }

    @Test
    public void testGenerateKey() throws Exception {
        LOG.info("testGenerateKey");

        final int workerId = WORKER_CMS;
        try {
            setCMSSignerProperties(workerId, false);
            workerSession.reloadConfiguration(workerId);

            // Check available aliases
            Set<String> aliases1 = getKeyAliases(workerId);

            if (aliases1.isEmpty()) {
                throw new Exception("getKeyAliases is not working or the slot is empty");
            }

            // If the key already exists, try to remove it first
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                workerSession.removeKey(new WorkerIdentifier(workerId), TEST_KEY_ALIAS);
                aliases1 = getKeyAliases(workerId);
            }
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " already exists and removing it failed");
            }

            // Generate a testkey
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());

            // Now expect the new TEST_KEY_ALIAS
            Set<String> expected = new HashSet<>(aliases1);
            expected.add(TEST_KEY_ALIAS);
            Set<String> aliases2 = getKeyAliases(workerId);
            assertEquals("new key added", expected, aliases2);
        } finally {
            try {
                workerSession.removeKey(new WorkerIdentifier(workerId), TEST_KEY_ALIAS);
            } catch (SignServerException ignored) {}
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Tests key generation when requesting a custom DN for the self-signed
     * certificate.
     */
    @Test
    public void testGenerateKey_withCustomDN() throws Exception {
        LOG.info("testGenerateKey_withCustomDN");

        final int workerId = WORKER_CMS;
        try {
            setCMSSignerProperties(workerId, false);
            final String expectedDN = "CN=My Custom DN, O=Custom Org, C=SE";
            workerSession.setWorkerProperty(workerId, "SELFSIGNED_DN", expectedDN);
            workerSession.setWorkerProperty(workerId, "DEFAULTKEY", TEST_KEY_ALIAS);
            workerSession.reloadConfiguration(workerId);

            // Check available aliases
            Set<String> aliases1 = getKeyAliases(workerId);

            if (aliases1.isEmpty()) {
                throw new Exception("getKeyAliases is not working or the slot is empty");
            }

            // If the key already exists, try to remove it first
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                workerSession.removeKey(new WorkerIdentifier(workerId), TEST_KEY_ALIAS);
                aliases1 = getKeyAliases(workerId);
            }
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " already exists and removing it failed");
            }

            // Generate a testkey
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());

            // Now expect the new DN
            final X509Certificate certAfter = (X509Certificate) workerSession.getSignerCertificate(new WorkerIdentifier(workerId));
            assertNotNull("New certificate", certAfter);
            assertEquals("New issuer DN", new X500Principal(expectedDN).getName(), certAfter.getIssuerX500Principal().getName());
            assertEquals("New subject DN", new X500Principal(expectedDN).getName(), certAfter.getSubjectX500Principal().getName());
        } finally {
            try {
                workerSession.removeKey(new WorkerIdentifier(workerId), TEST_KEY_ALIAS);
            } catch (SignServerException ignored) {}
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Test that generating a key with a specified key spec results in the
     * expected public exponent on the public key.
     *
     * @param spec key spec
     * @param expected public exponent
     */
    private void testGenerateKeyWithPublicExponent(final String spec,
                                                   final BigInteger expected)
        throws Exception {

        final int workerId = WORKER_CMS;

        try {
            setCMSSignerProperties(workerId, false);
            workerSession.reloadConfiguration(workerId);

            // Generate a key given a key spec
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", spec,
                                            "keywithexponent", pin.toCharArray());
            final Collection<KeyTestResult> testResults =
                    workerSession.testKey(new WorkerIdentifier(workerId), "keywithexponent", pin.toCharArray());
            for (final KeyTestResult testResult : testResults) {
                assertTrue("Testkey successful", testResult.isSuccess());
            }

            // Generate CSR, and check the public key's public exponent
            final PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA",
                "CN=test01GenerateKey,C=SE", null);
            AbstractCertReqData data = (AbstractCertReqData) workerSession
                .getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false, "keywithexponent");
            final PKCS10CertificationRequest req
                = new PKCS10CertificationRequest(data.toBinaryForm());

            final RSAPublicKey pubKey = (RSAPublicKey) testCase.getPublicKeyFromRequest(req);

            assertEquals("Returned public exponent",
                         expected, pubKey.getPublicExponent());
        } finally {
            try {
                workerSession.removeKey(new WorkerIdentifier(workerId), "keywithexponent");
            } catch (SignServerException ignored) {}
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Test generating a key with a custom specified public exponent in the spec.
     */
    @Test
    public void testGenerateKeyWithPublicExponentCustom() throws Exception {
        testGenerateKeyWithPublicExponent("2048 exp 5", BigInteger.valueOf(5));
    }

    /**
     * Test generateing a key with the default public exponent.
     */
    @Test
    public void testGenerateKeyWithPublicExponentDefault() throws Exception {
        testGenerateKeyWithPublicExponent("2048", BigInteger.valueOf(0x10001));
    }

    /**
     * Tests that key generation is not allowed when the number of keys has
     * reached the KEYGENERATIONLIMIT.
     * Also checks that when allowing for one more keys, the next key can be
     * generated.
     */
    @SuppressWarnings("ThrowableResultIgnored")
    @Test
    public void testKeyGenerationLimit() throws Exception {
        LOG.info("testKeyGenerationLimit");

        final int workerId = WORKER_CMS;
        try {
            setCMSSignerProperties(workerId, true);
            workerSession.reloadConfiguration(workerId);

            // Add a reference key
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", TEST_KEY_ALIAS_2, pin.toCharArray());

            // Check available aliases
            final int keys = getKeyAliases(workerId).size();

            // Set the current number of keys as maximum
            workerSession.setWorkerProperty(workerId, "KEYGENERATIONLIMIT", String.valueOf(keys));
            workerSession.reloadConfiguration(workerId);

            // Key generation should fail
            try {
                workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
                fail("Should have failed because of no space in token");
            } catch (TokenOutOfSpaceException expected) { // NOPMD
                // OK
            }

            // Allow for one more keys to be created
            workerSession.setWorkerProperty(workerId, "KEYGENERATIONLIMIT", String.valueOf(keys + 1));
            workerSession.reloadConfiguration(workerId);

            // Generate a new key
            try {
                workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
            } catch (CryptoTokenOfflineException ex) {
                fail("Should have worked but got: " + ex.getLocalizedMessage());
            }

            final int keys2 = getKeyAliases(workerId).size();
            assertEquals("one more key", keys + 1, keys2);

            // Key generation should fail
            try {
                workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
                fail("Should have failed because of no space in token");
            } catch (TokenOutOfSpaceException expected) { // NOPMD
                // OK
            }
        } finally {
            try {
                workerSession.removeKey(new WorkerIdentifier(workerId), TEST_KEY_ALIAS);
            } catch (SignServerException ignored) {}
            try {
                workerSession.removeKey(new WorkerIdentifier(workerId), TEST_KEY_ALIAS_2);
            } catch (SignServerException ignored) {}
            testCase.removeWorker(workerId);
        }
    }

    @Test
    public void testGenerateKey_separateToken() throws Exception {
        LOG.info("testGenerateKey_separateToken");

        final int tokenId = CRYPTO_TOKEN;
        try {
            setupCryptoTokenProperties(tokenId, false);
            workerSession.reloadConfiguration(tokenId);

            // Check available aliases
            Set<String> aliases1 = getKeyAliases(tokenId);

            if (aliases1.isEmpty()) {
                throw new Exception("getKeyAliases is not working or the slot is empty");
            }

            // If the key already exists, try to remove it first
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                workerSession.removeKey(new WorkerIdentifier(tokenId), TEST_KEY_ALIAS);
                aliases1 = getKeyAliases(tokenId);
            }
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " already exists and removing it failed");
            }

            // Generate a testkey
            workerSession.generateSignerKey(new WorkerIdentifier(tokenId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());

            // Now expect the new TEST_KEY_ALIAS
            Set<String> expected = new HashSet<>(aliases1);
            expected.add(TEST_KEY_ALIAS);
            Set<String> aliases2 = getKeyAliases(tokenId);
            assertEquals("new key added", expected, aliases2);

        } finally {
            try {
                workerSession.removeKey(new WorkerIdentifier(tokenId), TEST_KEY_ALIAS);
            } catch (SignServerException ignored) {}
            testCase.removeWorker(tokenId);
        }
    }

    @Test
    public void testRemoveKey() throws Exception {
        LOG.info("testRemoveKey");

        final int workerId = WORKER_CMS;
        try {
            setCMSSignerProperties(workerId, false);
            workerSession.reloadConfiguration(workerId);

            // Check available aliases
            Set<String> aliases1 = getKeyAliases(workerId);

            if (aliases1.isEmpty()) {
                throw new Exception("getKeyAliases is not working or the slot is empty");
            }

            if (!aliases1.contains(TEST_KEY_ALIAS)) {
                // Generate a testkey
                workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
                aliases1 = getKeyAliases(workerId);
            }
            if (!aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " did not exist and it could not be created");
            }

            // Remove the key
            workerSession.removeKey(new WorkerIdentifier(workerId), TEST_KEY_ALIAS);

            // Now expect the TEST_KEY_ALIAS to have been removed
            Set<String> aliases2 = getKeyAliases(workerId);
            Set<String> expected = new HashSet<>(aliases1);
            expected.remove(TEST_KEY_ALIAS);
            assertEquals("new key removed", expected, aliases2);
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    @Test
    public void testRemoveKey_separateToken() throws Exception {
        LOG.info("testRemoveKey_separateToken");

        final int tokenId = CRYPTO_TOKEN;
        try {
            setCMSSignerProperties(tokenId, false);
            workerSession.reloadConfiguration(tokenId);

            // Check available aliases
            Set<String> aliases1 = getKeyAliases(tokenId);

            if (aliases1.isEmpty()) {
                throw new Exception("getKeyAliases is not working or the slot is empty");
            }

            if (!aliases1.contains(TEST_KEY_ALIAS)) {
                // Generate a testkey
                workerSession.generateSignerKey(new WorkerIdentifier(tokenId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
                aliases1 = getKeyAliases(tokenId);
            }
            if (!aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " did not exist and it could not be created");
            }

            // Remove the key
            workerSession.removeKey(new WorkerIdentifier(tokenId), TEST_KEY_ALIAS);

            // Now expect the TEST_KEY_ALIAS to have been removed
            Set<String> aliases2 = getKeyAliases(tokenId);
            Set<String> expected = new HashSet<>(aliases1);
            expected.remove(TEST_KEY_ALIAS);
            assertEquals("new key removed", expected, aliases2);
        } finally {
            testCase.removeWorker(tokenId);
        }
    }

    /**
     * Test that missing the SHAREDLIBRARY property results
     * in a descriptive error reported by getFatalErrors().
     */
    @Test
    public void testNoSharedLibrary() throws Exception {
        LOG.info("testNoSharedLibrary");

        final int workerId = WORKER_XML;

        try {
            final String expectedPrefix =
                    "Failed to initialize crypto token: Missing SHAREDLIBRARYNAME property";
            setXMLSignerProperties(false);
            workerSession.removeWorkerProperty(workerId, "SHAREDLIBRARYNAME");
            workerSession.reloadConfiguration(workerId);

            final List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
            boolean foundError = false;

            for (final String error : errors) {
                if (error.startsWith(expectedPrefix)) {
                    foundError = true;
                    break;
                }
            }
            assertTrue("Should contain error: " + errors, foundError);
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Test that setting a non-existing P11 shared library results
     * in a descriptive error reported by getFatalErrors().
     */
    @Test
    public void testNonExistingSharedLibrary() throws Exception {
        LOG.info("testNonExistingSharedLibrary");

        final int workerId = WORKER_XML;

        try {
            final String expectedErrorPrefix =
                    "Failed to initialize crypto token: SHAREDLIBRARYNAME NonExistingLibrary is not referring to a defined value";
            setXMLSignerProperties(false);
            workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", "NonExistingLibrary");
            workerSession.reloadConfiguration(workerId);

            final List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
            boolean foundError = false;

            for (final String error : errors) {
                if (error.startsWith(expectedErrorPrefix)) {
                    foundError = true;
                    break;
                }
            }

            assertTrue("Should contain error about lib name but was: " + errors, foundError);
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Test that specifying the old property SHAREDLIBRARY not pointing to
     * a value defined in the P11 library list will give a deprecation error.
     */
    @Test
    public void testOldSharedLibraryPropertyPointingToUndefined() throws Exception {
        LOG.info("testOldSharedLibraryPropertyPointingToUndefined");

        final int workerId = WORKER_XML;

        try {
            final String expectedErrorPrefix =
                    "Failed to initialize crypto token: SHAREDLIBRARY is not permitted when pointing to a library not defined at deploy-time";
            setXMLSignerProperties(false);
            workerSession.removeWorkerProperty(workerId, "SHAREDLIBRARYNAME");
            workerSession.setWorkerProperty(workerId, "SHAREDLIBRARY", "/opt/lib/libundefinedp11.so");
            workerSession.reloadConfiguration(workerId);

            final List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
            boolean foundError = false;

            for (final String error : errors) {
                if (error.startsWith(expectedErrorPrefix)) {
                    foundError = true;
                    break;
                }
            }
            assertTrue("Should contain error about lib name but was: " + errors, foundError);
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Test that specifying the old property SHAREDLIBRARY pointing to a library
     * defined in deploy-time works.
     */
    @Test
    public void testOldSharedLibraryPropertyPointingToDefined() throws Exception {
        LOG.info("testOldSharedLibraryPropertyPointingToDefined");

        final int workerId = WORKER_XML;

        try {
            final String unexpectedErrorPrefix =
                    "Failed to initialize crypto token: SHAREDLIBRARY is not permitted when pointing to a library not defined at deploy-time";

            setXMLSignerProperties(false);
            workerSession.removeWorkerProperty(workerId, "SHAREDLIBRARYNAME");
            workerSession.setWorkerProperty(workerId, "SHAREDLIBRARY", sharedLibraryPath);
            workerSession.reloadConfiguration(workerId);

            final List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
            boolean foundError = false;

            for (final String error : errors) {
                if (error.startsWith(unexpectedErrorPrefix)) {
                    foundError = true;
                    break;
                }
            }

            assertFalse("Should not contain error: " + errors, foundError);
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Test that setting both the old and new property at the same time
     * is not allowed when referring to different libraries.
     */
    @Test
    public void testBothP11LibraryNameAndOldSharedLibraryProperty() throws Exception {
        LOG.info("testBothP11LibraryNameAndOldSharedLibraryProperty");

        final int workerId = WORKER_XML;

        try {
            final String expectedErrorPrefix =
                    "Failed to initialize crypto token: Can not specify both SHAREDLIBRARY and SHAREDLIBRARYNAME at the same time";

            setXMLSignerProperties(false);
            workerSession.setWorkerProperty(workerId, "SHAREDLIBRARY", sharedLibraryPath);
            workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", "SoftHSM");
            workerSession.reloadConfiguration(workerId);

            final List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
            boolean foundError = false;

            for (final String error : errors) {
                if (error.startsWith(expectedErrorPrefix)) {
                    foundError = true;
                    break;
                }
            }

            assertTrue("Should contain error: " + errors, foundError);
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Test that setting both the old and new property at the same time
     * is allowed for backwards compatability when pointing to the same
     * library.
     */
    @Test
    public void testBothP11LibraryNameAndOldSharedLibraryPropertyReferringSame() throws Exception {
        LOG.info("testBothP11LibraryNameAndOldSharedLibraryProperty");

        final int workerId = WORKER_XML;

        try {
            final String unexpectedErrorPrefix =
                    "Failed to initialize crypto token: Can not specify both SHAREDLIBRARY and SHAREDLIBRARYNAME at the same time";

            setXMLSignerProperties(false);
            workerSession.setWorkerProperty(workerId, "SHAREDLIBRARY", sharedLibraryPath);
            workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
            workerSession.reloadConfiguration(workerId);

            final List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
            boolean foundError = false;

            for (final String error : errors) {
                if (error.startsWith(unexpectedErrorPrefix)) {
                    foundError = true;
                    break;
                }
            }

            assertFalse("Should not contain error: " + errors, foundError);
        } finally {
            testCase.removeWorker(workerId);
        }
    }
}
