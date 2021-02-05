/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.p11ng.common;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
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
import static junit.framework.TestCase.assertTrue;
import static junit.framework.TestCase.fail;
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
import static org.junit.Assert.assertFalse;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.KeyTestResult;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.TokenOutOfSpaceException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.p11ng.common.cryptotoken.JackNJI11CryptoToken;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Test signing with all signers using a JackNJI11CryptoToken.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class P11NGSignTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(P11NGSignTest.class);

    private static final int CRYPTO_TOKEN = 20100;
    private static final int KEYWRAPPING_CRYPTO_TOKEN = 30100;
    private static final int WORKER_PDF = 20000;
    private static final int WORKER_TSA = 20001;
    private static final int WORKER_SOD = 20002;
    private static final int WORKER_CMS = 20003;
    private static final int WORKER_XML = 20004;
    private static final int WORKER_XML2 = 20014;
    private static final int WORKER_ODF = 20005;
    private static final int WORKER_OOXML = 20006;
    private static final int WORKER_MSA = 20007;
    private static final int WORKER_PLAIN_SIGNER = 25010;

    private static final String MSAUTHCODE_REQUEST_DATA =
    		"MIIBIwYKKwYBBAGCNwMCATCCARMGCSqGSIb3DQEHAaCCAQQEggEAVVSpOKf9zJYc" +
    		"tyvqgeHfO9JkobPYihUZcW9TbYzAUiJGEsElNCnLUaO0+MZG0TS7hlzqKKvrdXc7" +
    		"O/8C7c8YyjYF5YrLiaYS8cw3VbaQ2M1NWsLGzxF1pxsR9sMDJvfrryPaWj4eTi3Y" +
    		"UqRNS+GTa4quX4xbmB0KqMpCtrvuk4S9cgaJGwxmSE7N3omzvERTUxp7nVSHtms5" +
    		"lVMb082JFlABT1/o2mL5O6qFG119JeuS1+ZiL1AEy//gRs556OE1TB9UEQU2bFUm" +
    		"zBD4VHvkOOB/7X944v9lmK5y9sFv+vnf/34catL1A+ZNLwtd1Qq2VirqJxRK/T61" +
    		"QoSWj4rGpw==";

    private static final String TEST_KEY_ALIAS = "p11ngtestkey1234";
    private static final String TEST_KEY_ALIAS_2 = "somekey123ng";
    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenP11NG";
    private static final String KEYWRAPPING_CRYPTO_TOKEN_NAME = "TestKeyWrappingCryptoTokenP11NG";
    private static final String TEST_SECRETKEY = "secretkey123ng";
    private static final String TEST_PLAIN_SIGNER_NAME = "TestP11NGPlainSigner";

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

    public P11NGSignTest() throws FileNotFoundException {
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
        Assume.assumeTrue("P11NG".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.provider")));
        SignServerUtil.installBCProvider();
    }

    private void setupCryptoTokenProperties(final int tokenId) {
        // Setup token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(tokenId, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(tokenId, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1); // Test key
        workerSession.setWorkerProperty(tokenId, "CACHE_PRIVATEKEY", String.valueOf(false));
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

    private void setPDFSignerWithCryptoProperties() {
        // Setup worker
        workerSession.setWorkerProperty(WORKER_PDF, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(WORKER_PDF, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.pdfsigner.PDFSigner");
        workerSession.setWorkerProperty(WORKER_PDF, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(WORKER_PDF, "NAME", "PDFSignerP11");
        workerSession.setWorkerProperty(WORKER_PDF, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(WORKER_PDF, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(WORKER_PDF, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(WORKER_PDF, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(WORKER_PDF, "PIN", pin);
        workerSession.setWorkerProperty(WORKER_PDF, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(WORKER_PDF, "CACHE_PRIVATEKEY", String.valueOf(false));
    }

    /** Tests that the getCertificateRequest method generates a request. */
    @Test
    public void testGenerateCSR() throws Exception {
        LOG.info("testGenerateCSR");
        try {
            setPDFSignerWithCryptoProperties();
            workerSession.reloadConfiguration(WORKER_PDF);

            // Tests generating a CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
            AbstractCertReqData csr = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
            assertNotNull(csr);
            assertNotNull(csr.toBinaryForm());
            assertTrue(csr.toBinaryForm().length > 0);

            // Test for an non-existing key label
            setPDFSignerWithCryptoProperties();
            workerSession.setWorkerProperty(WORKER_PDF, "DEFAULTKEY", "NON-EXISTING-KEY-LABEL");
            workerSession.reloadConfiguration(WORKER_PDF);
            try {
                certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
                testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
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
        LOG.info("testGenerateCSR_separateToken");
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            setPDFSignerOnlyProperties();
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(WORKER_PDF);

            // Tests generating a CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
            AbstractCertReqData csr = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
            assertNotNull(csr);
            assertNotNull(csr.toBinaryForm());
            assertTrue(csr.toBinaryForm().length > 0);

            // Test for an non-existing key label
            workerSession.setWorkerProperty(WORKER_PDF, "DEFAULTKEY", "NON-EXISTING-KEY-LABEL");
            workerSession.reloadConfiguration(WORKER_PDF);
            try {
                certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
                testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
                fail("Should have thrown exception as the DEFAULTKEY does not exist");
            } catch (CryptoTokenOfflineException ok) { // NOPMD
                // OK
            }
        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
            testCase.removeWorker(WORKER_PDF);
        }
    }

    /**
     * Tests setting up a PDF Signer, giving it a certificate and sign a document.
     */
    @Test
    public void testPDFSigner_uncached() throws Exception {
        LOG.info("testPDFSigner_uncached");
        try {
            setPDFSignerWithCryptoProperties();
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
        LOG.info("testPDFSigner_uncached_separateToken");
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
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
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);

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

    private void setTimeStampSignerProperties() throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(WORKER_TSA, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(WORKER_TSA, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.tsa.TimeStampSigner");
        workerSession.setWorkerProperty(WORKER_TSA, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(WORKER_TSA, "NAME", "TSSignerP11");
        workerSession.setWorkerProperty(WORKER_TSA, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(WORKER_TSA, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(WORKER_TSA, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(WORKER_TSA, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(WORKER_TSA, "PIN", pin);
        workerSession.setWorkerProperty(WORKER_TSA, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(WORKER_TSA, "DEFAULTTSAPOLICYOID", "1.2.3");
        workerSession.setWorkerProperty(WORKER_TSA, "CACHE_PRIVATEKEY", String.valueOf(false));
        workerSession.setWorkerProperty(WORKER_TSA, "ACCEPTANYPOLICY", "true");

        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_TSA, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_TSA), certReqInfo, false);

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
     * Tests setting up a TimeStamp Signer, giving it a certificate and request a time-stamp token.
     */
    @Test
    public void testTSSigner_uncached() throws Exception {
        LOG.info("testTSSigner_uncached");
        try {
            setTimeStampSignerProperties();
            workerSession.reloadConfiguration(WORKER_TSA);
            tsSigner();
        } finally {
            testCase.removeWorker(WORKER_TSA);
        }
    }

    private void tsSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_TSA, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_TSA), certReqInfo, false);

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
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
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

    private void setMRTDSODSignerProperties() {
        // Setup worker
        workerSession.setWorkerProperty(20002, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(20002, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.mrtdsodsigner.MRTDSODSigner");
        workerSession.setWorkerProperty(20002, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(20002, "NAME", "SODSignerP11");
        workerSession.setWorkerProperty(20002, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(20002, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(20002, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(20002, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(20002, "PIN", pin);
        workerSession.setWorkerProperty(20002, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(20002, "CACHE_PRIVATEKEY", String.valueOf(false));
    }

    /**
     * Tests setting up a MRTD SOD Signer, giving it a certificate and requests an SOd.
     */
    @Test
    public void testMRTDSODSigner_uncached() throws Exception {
        LOG.info("testMRTDSODSigner_uncached");
        final int workerId = WORKER_SOD;
        try {
            setMRTDSODSignerProperties();
            workerSession.reloadConfiguration(workerId);

            mrtdsodSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void mrtdsodSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + 20002, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(20002), certReqInfo, false);

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

    private void setCMSSignerProperties(final int workerId) {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.CMSSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "CMSSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(workerId, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
    }

    /**
     * Tests setting up a CMS Signer, giving it a certificate and sign a file.
     */
    @Test
    public void testCMSSigner_uncached() throws Exception {
        LOG.info("testCMSSigner_uncached");
        final int workerId = WORKER_CMS;
        try {
            setCMSSignerProperties(workerId);
            workerSession.reloadConfiguration(workerId);

            cmsSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void cmsSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + 20003, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(20003), certReqInfo, false);

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
        testCase.signGenericDocument(20003, "Sample data".getBytes());
    }

    private void setXMLSignerProperties() {
        // Setup worker
        workerSession.setWorkerProperty(20004, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(20004, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.xmlsigner.XMLSigner");
        workerSession.setWorkerProperty(20004, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(20004, "NAME", "XMLSignerP11");
        workerSession.setWorkerProperty(20004, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(20004, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(20004, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(20004, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(20004, "PIN", pin);
        workerSession.setWorkerProperty(20004, "DEFAULTKEY", existingKey1);
    }

    private void setXMLSignerPropertiesReferingToken(final int workerId, String alias) {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.xmlsigner.XMLSigner");
        workerSession.setWorkerProperty(workerId, "NAME", "XMLSignerRefering");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");

        if (alias != null) {
            workerSession.setWorkerProperty(workerId, "DEFAULTKEY", alias);
        } else {
            workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        }
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
    }

    /**
     * Tests setting up a XML Signer, giving it a certificate and sign a document.
     * Uses a newly generated key-pair to be sure the key entry does not already have a certificate.
     */
    @Test
    public void testXMLSigner_uncached() throws Exception {
        LOG.info("testXMLSigner_uncached");
        final int workerId = WORKER_XML;
        final String alias = "xmlsignertestkey";
        try {
            setXMLSignerProperties();
            workerSession.reloadConfiguration(workerId);
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", alias, null);
            workerSession.setWorkerProperty(workerId, "DEFAULTKEY", alias);
            workerSession.reloadConfiguration(workerId);
            xmlSigner(workerId);
        } finally {
            workerSession.removeKey(new WorkerIdentifier(workerId), alias);
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Exercises a signer using a separate token and where the private key is
     * cached (in the worker).
     * Uses a newly generated key-pair to be sure the key entry does not already have a certificate.
     */
    @Test
    public void testXMLSigner_separateToken() throws Exception {
        LOG.info("testXMLSigner_separateToken");
        final int workerId = WORKER_XML2;
        final String alias = "xmlsignertestkey";
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setXMLSignerPropertiesReferingToken(workerId, null);
            workerSession.reloadConfiguration(workerId);
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", alias, null);
            workerSession.setWorkerProperty(workerId, "DEFAULTKEY", alias);
            workerSession.reloadConfiguration(workerId);

            xmlSigner(workerId);
        } finally {
            workerSession.removeKey(new WorkerIdentifier(workerId), alias);
            testCase.removeWorker(workerId);
        }
    }

    private void xmlSigner(final int workerId) throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

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

    private void setODFSignerProperties() {
        // Setup worker
        workerSession.setWorkerProperty(20005, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(20005, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.odfsigner.ODFSigner");
        workerSession.setWorkerProperty(20005, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(20005, "NAME", "ODFSignerP11");
        workerSession.setWorkerProperty(20005, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(20005, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(20005, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(20005, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(20005, "PIN", pin);
        workerSession.setWorkerProperty(20005, "DEFAULTKEY", existingKey1);
    }

    /**
     * Tests setting up a ODF Signer, giving it a certificate and sign a document.
     */
    @Test
    public void testODFSigner_uncached() throws Exception {
        LOG.info("testODFSigner_uncached");
        final int workerId = WORKER_ODF;
        try {
            setODFSignerProperties();
            workerSession.reloadConfiguration(workerId);

            odfSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void odfSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + 20005, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(20005), certReqInfo, false);

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

    private void setOOXMLSignerProperties() {
        // Setup worker
        workerSession.setWorkerProperty(20006, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(20006, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.ooxmlsigner.OOXMLSigner");
        workerSession.setWorkerProperty(20006, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(20006, "NAME", "OOXMLSignerP11");
        workerSession.setWorkerProperty(20006, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(20006, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(20006, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(20006, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(20006, "PIN", pin);
        workerSession.setWorkerProperty(20006, "DEFAULTKEY", existingKey1);
    }

    /**
     * Tests setting up a OOXML Signer, giving it a certificate and sign a document.
     */
    @Test
    public void testOOXMLSigner_uncached() throws Exception {
        LOG.info("testOOXMLSigner_uncached");
        final int workerId = WORKER_OOXML;
        try {
            setOOXMLSignerProperties();
            workerSession.reloadConfiguration(workerId);
            ooxmlSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void ooxmlSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + 20006, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(20006), certReqInfo, false);

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

    private void setMSAuthTimeStampSignerProperties() {
        // Setup worker
        workerSession.setWorkerProperty(20007, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(20007, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.tsa.MSAuthCodeTimeStampSigner");
        workerSession.setWorkerProperty(20007, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(20007, "NAME", "MSAuthTSSignerP11");
        workerSession.setWorkerProperty(20007, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(20007, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(20007, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(20007, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(20007, "PIN", pin);
        workerSession.setWorkerProperty(20007, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(20007, "DEFAULTTSAPOLICYOID", "1.2.3");
    }

    /**
     * Tests setting up a MSAuthCodeTimeStamp Signer, giving it a certificate and request a time-stamp token.
     */
    @Test
    public void testMSAuthTSSigner_uncached() throws Exception {
        LOG.info("testMSAuthTSSigner_uncached");
        final int workerId = WORKER_MSA;
        try {
            setMSAuthTimeStampSignerProperties();
            workerSession.reloadConfiguration(workerId);
            msauthTSSigner();
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void msauthTSSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + 20007, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(20007), certReqInfo, false);

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

        for (SignerInformation signer : signerInfos) {
            Collection certCollection = certStore.getMatches(signer.getSID());

            Iterator certIt = certCollection.iterator();
            X509CertificateHolder signerCert = (X509CertificateHolder) certIt.next();

            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerCert))) {
                verified++;
            }
        }

        assertEquals("signer verified", 1, verified);
    }

    /**
     * Test having default JackNJI11CryptoToken properties.
     * Tests setting up a CMS Signer, giving it a certificate and sign a file.
     */
    @Test
    public void testDefaultGlobalProperties() throws Exception {
        LOG.info("testDefaultGlobalProperties");
        final int workerId = WORKER_CMS;
        try {
            // Setup worker
            workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
            workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.CMSSigner");
            workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "DEFAULT.SHAREDLIBRARYNAME", sharedLibraryName);
            workerSession.setWorkerProperty(workerId, "NAME", "CMSSignerP11");
            workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
            workerSession.setWorkerProperty(workerId, "PIN", pin);
            workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
            workerSession.setWorkerProperty(workerId, "SLOTLABELTYPE", "SLOT_NUMBER");
            workerSession.setWorkerProperty(workerId, "SLOTLABELVALUE", slot);
            workerSession.reloadConfiguration(workerId);

            cmsSigner();
        } finally {
            testCase.removeWorker(workerId);
            globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "DEFAULT.SHAREDLIBRARY");
            globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "DEFAULT.SHAREDLIBRARYNAME");
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
            setCMSSignerProperties(workerId);
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
            setCMSSignerProperties(workerId);
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
            setCMSSignerProperties(workerId);
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
            setupCryptoTokenProperties(tokenId);
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
            setCMSSignerProperties(workerId);
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
            setCMSSignerProperties(tokenId);
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
            setXMLSignerProperties();
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
            setXMLSignerProperties();
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

            assertTrue("Should contain error about lib name but was: " + errors,
                        foundError);
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

            setXMLSignerProperties();
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

    /**
     * Tests that signer gives fatal error when default key is associated with dummy certificate.
     */
    @Test
    public void testFatalErrorExistsWithDummyCertificate() throws Exception {
        LOG.info("testFatalErrorExistsWithDummyCertificate");
        final int workerId = WORKER_XML;
        try {

            setupCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            // Check available aliases
            Set<String> aliases1 = getKeyAliases(CRYPTO_TOKEN);

            // If the key already exists, try to remove it first
            if (aliases1.contains(TEST_KEY_ALIAS_2)) {
                workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN), TEST_KEY_ALIAS_2);
                aliases1 = getKeyAliases(CRYPTO_TOKEN);
            }
            if (aliases1.contains(TEST_KEY_ALIAS_2)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS_2 + " already exists and removing it failed");
            }

            workerSession.generateSignerKey(new WorkerIdentifier(CRYPTO_TOKEN), "RSA", "2048", TEST_KEY_ALIAS_2, pin.toCharArray());

            // Now expect the new TEST_KEY_ALIAS_2
            Set<String> expected = new HashSet<>(aliases1);
            expected.add(TEST_KEY_ALIAS_2);
            Set<String> aliases2 = getKeyAliases(CRYPTO_TOKEN);
            assertEquals("new key added", expected, aliases2);

            setXMLSignerPropertiesReferingToken(workerId, TEST_KEY_ALIAS_2);
            workerSession.reloadConfiguration(workerId);

            String errorMessage = "No signer certificate available";
            StaticWorkerStatus stat = (StaticWorkerStatus) workerSession.getStatus(new WorkerIdentifier(workerId));
            assertFalse(stat.getFatalErrors().isEmpty());
            assertTrue("Fatal Errors should contain error message ", stat.getFatalErrors().contains(errorMessage));

        } finally {
            workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN), TEST_KEY_ALIAS_2);
            testCase.removeWorker(CRYPTO_TOKEN);
            testCase.removeWorker(workerId);
        }
    }

    private void cryptoTokenPropertiesHelper(final String signatureAlgorithm) {
        // Setup token
        workerSession.setWorkerProperty(CRYPTO_TOKEN, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(CRYPTO_TOKEN, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(CRYPTO_TOKEN, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(CRYPTO_TOKEN, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(CRYPTO_TOKEN, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(CRYPTO_TOKEN, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(CRYPTO_TOKEN, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(CRYPTO_TOKEN, "PIN", pin);
        workerSession.setWorkerProperty(CRYPTO_TOKEN, "DEFAULTKEY", existingKey1); // Test key
        workerSession.setWorkerProperty(CRYPTO_TOKEN, "SIGNATUREALGORITHM", signatureAlgorithm);
    }

    private void testSigningWithProvidedSigAlgo(final String signatureAlgorithm) throws Exception {
        LOG.info(">testSigningWithProvidedSigAlgo(" + signatureAlgorithm + ")");
        try {
            cryptoTokenPropertiesHelper(signatureAlgorithm);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            Collection<KeyTestResult> results = workerSession.testKey(new WorkerIdentifier(CRYPTO_TOKEN), existingKey1, pin.toCharArray());
            assertEquals("Results size: " + results, 1, results.size());
            for (KeyTestResult result : results) {
                assertTrue("Success for " + result, result.isSuccess());
            }
        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }

    /**
     * Test signing by JackNJI11CryptoToken key with SHA256withRSA signature algorithm.
     */
    @Test
    public void testSign_SHA256withRSA_JackNJI11CryptoToken() throws Exception {
        LOG.info("testSign_SHA256withRSA_JackNJI11CryptoToken");
        testSigningWithProvidedSigAlgo("SHA256withRSA");
    }

    /**
     * Test signing by JackNJI11CryptoToken key with SHA512withRSA signature algorithm.
     */
    @Test
    public void testSign_SHA512withRSA_JackNJI11CryptoToken() throws Exception {
        LOG.info("testSign_SHA512withRSA_JackNJI11CryptoToken");
        testSigningWithProvidedSigAlgo("SHA512withRSA");
    }

    /**
     * Test signing by JackNJI11CryptoToken key with SHA256withRSAandMGF1 signature algorithm.
     */
    @Test
    public void testSign_SHA256withRSAandMGF1_JackNJI11CryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.PSS_SIGNATURE_ALGORITHM_SUPPORTED")));
        LOG.info("testSign_SHA256withRSAandMGF1_JackNJI11CryptoToken");
        testSigningWithProvidedSigAlgo("SHA256withRSAandMGF1");
    }

    /**
     * Test signing by JackNJI11CryptoToken key with SHA384withRSAandMGF1 signature algorithm.
     */
    @Test
    public void testSign_SHA384withRSAandMGF1_JackNJI11CryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.PSS_SIGNATURE_ALGORITHM_SUPPORTED")));
        LOG.info("testSign_SHA384withRSAandMGF1_JackNJI11CryptoToken");
        testSigningWithProvidedSigAlgo("SHA384withRSAandMGF1");
    }

    /**
     * Test signing by JackNJI11CryptoToken key with SHA512withRSAandMGF1 signature algorithm.
     */
    @Test
    public void testSign_SHA512withRSAandMGF1_JackNJI11CryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.PSS_SIGNATURE_ALGORITHM_SUPPORTED")));
        LOG.info("testSign_SHA512withRSAandMGF1_JackNJI11CryptoToken");
        testSigningWithProvidedSigAlgo("SHA512withRSAandMGF1");
    }

    private void testSigningWithProvidedSigAlgo_KeyWrappingCryptoToken(final String signatureAlgorithm) throws Exception {
        LOG.info(">testSigningWithProvidedSigAlgo_KeyWrappingCryptoToken(" + signatureAlgorithm + ")");
        try {
            cryptoTokenPropertiesHelper("SHA256withRSA");
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            // Check available aliases
            Set<String> aliases1 = getKeyAliases(CRYPTO_TOKEN);

            // If the key already exists, try to remove it first
            if (aliases1.contains(TEST_SECRETKEY)) {
                workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN), TEST_SECRETKEY);
                aliases1 = getKeyAliases(CRYPTO_TOKEN);
            }
            if (aliases1.contains(TEST_SECRETKEY)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS_2 + " already exists and removing it failed");
            }

            workerSession.generateSignerKey(new WorkerIdentifier(CRYPTO_TOKEN), "AES", "256", TEST_SECRETKEY, null);

            // Now expect the new TEST_SECRETKEY
            Set<String> expected = new HashSet<>(aliases1);
            expected.add(TEST_SECRETKEY);
            Set<String> aliases2 = getKeyAliases(CRYPTO_TOKEN);
            assertEquals("new key added", expected, aliases2);

            workerSession.setWorkerProperty(KEYWRAPPING_CRYPTO_TOKEN, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
            workerSession.setWorkerProperty(KEYWRAPPING_CRYPTO_TOKEN, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.p11ng.common.cryptotoken.JackNJI11KeyWrappingCryptoWorker");
            workerSession.setWorkerProperty(KEYWRAPPING_CRYPTO_TOKEN, "NAME", KEYWRAPPING_CRYPTO_TOKEN_NAME);
            workerSession.setWorkerProperty(KEYWRAPPING_CRYPTO_TOKEN, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
            workerSession.setWorkerProperty(KEYWRAPPING_CRYPTO_TOKEN, "DEFAULTKEY", TEST_SECRETKEY);
            workerSession.setWorkerProperty(KEYWRAPPING_CRYPTO_TOKEN, "SIGNATUREALGORITHM", signatureAlgorithm);
            workerSession.reloadConfiguration(KEYWRAPPING_CRYPTO_TOKEN);

            workerSession.generateSignerKey(new WorkerIdentifier(KEYWRAPPING_CRYPTO_TOKEN), "RSA", "2048", TEST_KEY_ALIAS_2, null);
            Collection<KeyTestResult> results = workerSession.testKey(new WorkerIdentifier(KEYWRAPPING_CRYPTO_TOKEN), TEST_KEY_ALIAS_2, pin.toCharArray());
            assertEquals("Results size: " + results, 1, results.size());
            for (KeyTestResult result : results) {
                assertTrue("Success for " + result, result.isSuccess());
            }
        } finally {
            workerSession.removeKey(new WorkerIdentifier(KEYWRAPPING_CRYPTO_TOKEN), TEST_KEY_ALIAS_2);
            testCase.removeWorker(KEYWRAPPING_CRYPTO_TOKEN);
            workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN), TEST_SECRETKEY);
            testCase.removeWorker(CRYPTO_TOKEN);
        }

    }

    /**
     * Test signing by JackNJI11KeyWrappingCryptoToken key with SHA256withRSA signature algorithm.
     */
    @Test
    public void testSign_SHA256withRSA_KeyWrappingCryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.KEY_WRAPPING_UNWRAPPING_SUPPORTED")));
        LOG.info("testSign_SHA256withRSA_KeyWrappingCryptoToken");
        testSigningWithProvidedSigAlgo_KeyWrappingCryptoToken("SHA256withRSA");
    }

    /**
     * Test signing by JackNJI11KeyWrappingCryptoToken key with SHA512withRSA signature algorithm.
     */
    @Test
    public void testSign_SHA512withRSA_KeyWrappingCryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.KEY_WRAPPING_UNWRAPPING_SUPPORTED")));
        LOG.info("testSign_SHA512withRSA_KeyWrappingCryptoToken");
        testSigningWithProvidedSigAlgo_KeyWrappingCryptoToken("SHA512withRSA");
    }

    /**
     * Test signing by JackNJI11KeyWrappingCryptoToken key with SHA256withRSAandMGF1 signature algorithm.
     */
    @Test
    public void testSign_SHA256withRSAandMGF1_KeyWrappingCryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.KEY_WRAPPING_UNWRAPPING_SUPPORTED")));
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.PSS_SIGNATURE_ALGORITHM_SUPPORTED")));
        LOG.info("testSign_SHA256withRSAandMGF1_KeyWrappingCryptoToken");
        testSigningWithProvidedSigAlgo_KeyWrappingCryptoToken("SHA256withRSAandMGF1");
    }

    /**
     * Test signing by JackNJI11KeyWrappingCryptoToken key with SHA512withRSAandMGF1 signature algorithm.
     */
    @Test
    public void testSign_SHA512withRSAandMGF1_KeyWrappingCryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.KEY_WRAPPING_UNWRAPPING_SUPPORTED")));
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.PSS_SIGNATURE_ALGORITHM_SUPPORTED")));
        LOG.info("testSign_SHA512withRSAandMGF1_KeyWrappingCryptoToken");
        testSigningWithProvidedSigAlgo_KeyWrappingCryptoToken("SHA512withRSAandMGF1");
    }

    private void setUpPlainSigner() throws Exception {
        setPlainSignerProperties();
        workerSession.reloadConfiguration(WORKER_PLAIN_SIGNER);

        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PLAIN_SIGNER, null);
        AbstractCertReqData reqData = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_PLAIN_SIGNER), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(WORKER_PLAIN_SIGNER, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(WORKER_PLAIN_SIGNER, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(WORKER_PLAIN_SIGNER);

    }

    private void setUpPlainSignerWithKeyWrappingCryptoToken() throws Exception {

        cryptoTokenPropertiesHelper("SHA256withRSA");
        workerSession.reloadConfiguration(CRYPTO_TOKEN);

        // Check available aliases
        Set<String> aliases1 = getKeyAliases(CRYPTO_TOKEN);

        // If the key already exists, try to remove it first
        if (aliases1.contains(TEST_SECRETKEY)) {
            workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN), TEST_SECRETKEY);
            aliases1 = getKeyAliases(CRYPTO_TOKEN);
        }
        if (aliases1.contains(TEST_SECRETKEY)) {
            throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS_2 + " already exists and removing it failed");
        }

        workerSession.generateSignerKey(new WorkerIdentifier(CRYPTO_TOKEN), "AES", "256", TEST_SECRETKEY, null);

        // Now expect the new TEST_SECRETKEY
        Set<String> expected = new HashSet<>(aliases1);
        expected.add(TEST_SECRETKEY);
        Set<String> aliases2 = getKeyAliases(CRYPTO_TOKEN);
        assertEquals("new key added", expected, aliases2);

        workerSession.setWorkerProperty(KEYWRAPPING_CRYPTO_TOKEN, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(KEYWRAPPING_CRYPTO_TOKEN, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.p11ng.common.cryptotoken.JackNJI11KeyWrappingCryptoWorker");
        workerSession.setWorkerProperty(KEYWRAPPING_CRYPTO_TOKEN, "NAME", KEYWRAPPING_CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(KEYWRAPPING_CRYPTO_TOKEN, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(KEYWRAPPING_CRYPTO_TOKEN, "DEFAULTKEY", TEST_SECRETKEY);
        workerSession.reloadConfiguration(KEYWRAPPING_CRYPTO_TOKEN);

        workerSession.generateSignerKey(new WorkerIdentifier(KEYWRAPPING_CRYPTO_TOKEN), "RSA", "2048", TEST_KEY_ALIAS_2, null);

        setPlainSignerPropertiesWithKeyWrappingCryptoToken();
        workerSession.reloadConfiguration(WORKER_PLAIN_SIGNER);

        // Generate CSR
        final ISignerCertReqInfo req
                = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PLAIN_SIGNER, null);
        AbstractCertReqData reqData
                = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_PLAIN_SIGNER), req, false, TEST_KEY_ALIAS_2);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(WORKER_PLAIN_SIGNER, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(WORKER_PLAIN_SIGNER, Collections.singletonList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(WORKER_PLAIN_SIGNER);

    }

    private void setPlainSignerProperties() {
        // Setup token
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.PlainSigner");
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "NAME", TEST_PLAIN_SIGNER_NAME);
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "PIN", pin);
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "DEFAULTKEY", existingKey1); // Test key
    }

    private void setPlainSignerPropertiesWithKeyWrappingCryptoToken() {
        // Setup token
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.PlainSigner");
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "CRYPTOTOKEN", KEYWRAPPING_CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "NAME", TEST_PLAIN_SIGNER_NAME);
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "DEFAULTKEY", TEST_KEY_ALIAS_2);
    }

    private SimplifiedResponse sign_With_PlainSigner(final byte[] data) throws Exception {
        try {
            setUpPlainSigner();
            workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "SIGNATUREALGORITHM", "NONEwithRSA");
            workerSession.reloadConfiguration(WORKER_PLAIN_SIGNER);

            final int reqid = 37;
            final GenericSignRequest signRequest
                    = new GenericSignRequest(reqid, data);

            final GenericSignResponse res
                    = (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_PLAIN_SIGNER), signRequest, new RemoteRequestContext());
            byte[] signedBytes = res.getProcessedData();

            Certificate signerCertificate = res.getSignerCertificate();
            return new SimplifiedResponse(signedBytes, signerCertificate);

        } finally {
            testCase.removeWorker(WORKER_PLAIN_SIGNER);
        }
    }

    private SimplifiedResponse sign_With_PlainSigner_WrappedKey(final byte[] data) throws Exception {
        try {
            setUpPlainSignerWithKeyWrappingCryptoToken();
            workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "SIGNATUREALGORITHM", "NONEwithRSA");
            workerSession.reloadConfiguration(WORKER_PLAIN_SIGNER);

            final int reqid = 37;
            final GenericSignRequest signRequest
                    = new GenericSignRequest(reqid, data);

            final GenericSignResponse res
                    = (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_PLAIN_SIGNER), signRequest, new RemoteRequestContext());
            byte[] signedBytes = res.getProcessedData();

            Certificate signerCertificate = res.getSignerCertificate();
            return new SimplifiedResponse(signedBytes, signerCertificate);

        } finally {
            testCase.removeWorker(WORKER_PLAIN_SIGNER);
            workerSession.removeKey(new WorkerIdentifier(KEYWRAPPING_CRYPTO_TOKEN), TEST_KEY_ALIAS_2);
            testCase.removeWorker(KEYWRAPPING_CRYPTO_TOKEN);
            workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN), TEST_SECRETKEY);
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }

    private void assertSignedAndVerifiable(byte[] plainText, String signatureAlgorithm, SimplifiedResponse resp) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(signatureAlgorithm, "BC");
        signature.initVerify(resp.getSignerCertificate());
        signature.update(plainText);
        assertTrue("consistent signature", signature.verify(resp.getProcessedData()));
    }

    /**
     * Test that Signing works and signature is verified when signature algorithm is NONEwithRSA and input is SHA-256 hash digest.
     */
    @Test
    public void testNONESigning_RSA_SHA256_structure_JackNJI11CryptoToken() throws Exception {
        LOG.info("testNONESigning_RSA_SHA256_structure_JackNJI11CryptoToken");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes(StandardCharsets.US_ASCII);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plainText);
        byte[] hash = md.digest();

        // Taken from RFC 3447, page 42 for SHA-256, create input for signing
        byte[] modifierBytes = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(modifierBytes);
        baos.write(hash);

        SimplifiedResponse resp = sign_With_PlainSigner(baos.toByteArray());
        assertSignedAndVerifiable(plainText, "SHA256withRSA", resp);
    }

    /**
     * Test that signing through wrapped key works and signature is verified when signature
     * algorithm is NONEwithRSA and input is SHA-256 hash digest.
     */
    @Test
    public void testNONESigning_RSA_SHA256_structure_JackNJI11KeyWrappingCryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.KEY_WRAPPING_UNWRAPPING_SUPPORTED")));

        LOG.info("testNONESigning_RSA_SHA256_structure_JackNJI11KeyWrappingCryptoToken");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes(StandardCharsets.US_ASCII);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plainText);
        byte[] hash = md.digest();

        // Taken from RFC 3447, page 42 for SHA-256, create input for signing
        byte[] modifierBytes = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(modifierBytes);
        baos.write(hash);

        SimplifiedResponse resp = sign_With_PlainSigner_WrappedKey(baos.toByteArray());
        assertSignedAndVerifiable(plainText, "SHA256withRSA", resp);
    }

    /**
     * Test that signing works and signature is verified when signature algorithm is NONEwithRSA and input is SHA-512 hash digest.
     */
    @Test
    public void testNONESigning_RSA_SHA512_structure_JackNJI11CryptoToken() throws Exception {
        LOG.info("testNONESigning_RSA_SHA512_structure_JackNJI11CryptoToken");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes(StandardCharsets.US_ASCII);
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(plainText);
        byte[] hash = md.digest();

        // Taken from RFC 3447, page 42 for SHA-512, create input for signing
        byte[] modifierBytes = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(modifierBytes);
        baos.write(hash);

        SimplifiedResponse resp = sign_With_PlainSigner(baos.toByteArray());
        assertSignedAndVerifiable(plainText, "SHA512withRSA", resp);
    }

    /**
     * Test that signing through wrapped key works and signature is verified
     * when signature algorithm is NONEwithRSA and input is SHA-512 hash digest.
     */
    @Test
    public void testNONESigning_RSA_SHA512_structure_JackNJI11KeyWrappingCryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.KEY_WRAPPING_UNWRAPPING_SUPPORTED")));

        LOG.info("testNONESigning_RSA_SHA512_structure_JackNJI11KeyWrappingCryptoToken");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes(StandardCharsets.US_ASCII);
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(plainText);
        byte[] hash = md.digest();

        // Taken from RFC 3447, page 42 for SHA-512, create input for signing
        byte[] modifierBytes = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(modifierBytes);
        baos.write(hash);

        SimplifiedResponse resp = sign_With_PlainSigner_WrappedKey(baos.toByteArray());
        assertSignedAndVerifiable(plainText, "SHA512withRSA", resp);
    }

}
