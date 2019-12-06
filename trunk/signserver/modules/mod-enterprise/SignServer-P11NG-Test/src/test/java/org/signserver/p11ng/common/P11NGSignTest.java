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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
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
import org.bouncycastle.operator.OperatorCreationException;
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
import org.signserver.common.InvalidWorkerIdException;
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
    public void setUp() throws Exception {
        Assume.assumeTrue("P11NG".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.provider")));
        SignServerUtil.installBCProvider();
    }

    private void setupCryptoTokenProperties(final int tokenId, final boolean cache) throws Exception {
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
        workerSession.setWorkerProperty(tokenId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    private void setPDFSignerOnlyProperties(final int workerId) throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.pdfsigner.PDFSigner");
        workerSession.setWorkerProperty(workerId, "NAME", "PDFSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
    }

    private void setPDFSignerWithCryptoProperties(final int workerId, final boolean cache) throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.pdfsigner.PDFSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "PDFSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(workerId, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    /** Tests that the getCertificateRequest method generates a request. */
    @Test
    public void testGenerateCSR() throws Exception {
        LOG.info("testGenerateCSR");
        try {
            setPDFSignerWithCryptoProperties(WORKER_PDF, false);
            workerSession.reloadConfiguration(WORKER_PDF);
            
            // Tests generating a CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
            AbstractCertReqData csr = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
            assertNotNull(csr);
            assertNotNull(csr.toBinaryForm());
            testCase.assertTrue(csr.toBinaryForm().length > 0);
            
            // Test for an non-existing key label
            setPDFSignerWithCryptoProperties(WORKER_PDF, false);
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
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            setPDFSignerOnlyProperties(WORKER_PDF);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(WORKER_PDF);

            // Tests generating a CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
            AbstractCertReqData csr = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
            assertNotNull(csr);
            assertNotNull(csr.toBinaryForm());
            testCase.assertTrue(csr.toBinaryForm().length > 0);

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
            setPDFSignerWithCryptoProperties(WORKER_PDF, false);
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
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            setPDFSignerOnlyProperties(WORKER_PDF);
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
        workerSession.uploadSignerCertificateChain(WORKER_PDF, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
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
    
    private void setTimeStampSignerProperties(final int workerId, final boolean cache) throws IOException, CryptoTokenOfflineException, InvalidWorkerIdException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.tsa.TimeStampSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "TSSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(workerId, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "DEFAULTTSAPOLICYOID", "1.2.3");
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
        workerSession.setWorkerProperty(workerId, "ACCEPTANYPOLICY", "true");
        
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo())
                .addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping).toASN1Primitive())
                .build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));
       
        // Install certificate and chain
        workerSession.uploadSignerCertificate(workerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(workerId, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(workerId);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
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
            setTimeStampSignerProperties(WORKER_TSA, false);
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
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).addExtension(org.bouncycastle.asn1.x509.X509Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(WORKER_TSA, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(WORKER_TSA, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
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
        final TimeStampResponse timeStampResponse = new TimeStampResponse((byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        assertEquals("Token granted", PKIStatus.GRANTED, timeStampResponse.getStatus());
        assertNotNull("Got timestamp token", timeStampResponse.getTimeStampToken());
    }
    
    private void setMRTDSODSignerProperties(final int workerId, final boolean cache) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.mrtdsodsigner.MRTDSODSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "SODSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(workerId, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }
    
    /**
     * Tests setting up a MRTD SOD Signer, giving it a certificate and requests an SOd.
     */
    @Test
    public void testMRTDSODSigner_uncached() throws Exception {
        LOG.info("testMRTDSODSigner_uncached");
        final int workerId = WORKER_SOD;
        try {
            setMRTDSODSignerProperties(workerId, false);
            workerSession.reloadConfiguration(workerId);
            
            mrtdsodSigner(workerId);
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void mrtdsodSigner(final int workerId) throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder issuerCert = new JcaX509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), new X500Name("CN=TestP11 Issuer"), issuerKeyPair.getPublic()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(workerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(workerId, Arrays.asList(cert.getEncoded(), issuerCert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(workerId);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        HashMap<Integer, byte[]> dgs = new HashMap<>();
        dgs.put(1, Base64.decode("PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=".getBytes(StandardCharsets.US_ASCII)));
        dgs.put(2, Base64.decode("PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=".getBytes(StandardCharsets.US_ASCII)));
        dgs.put(3, Base64.decode("PJaDAX+eS/M9D77dJr8UP9ct6bndFFRBt18GBAR+oo4=".getBytes(StandardCharsets.US_ASCII)));
        final SODSignRequest signRequest = new SODSignRequest(233, dgs);
        final SODSignResponse res = (SODSignResponse) processSession.process(new WorkerIdentifier(workerId), signRequest, new RemoteRequestContext());
        Certificate signercert = res.getSignerCertificate();
        assertNotNull(signercert);
    }
    
    private void setCMSSignerProperties(final int workerId) throws IOException {
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
            
            cmsSigner(workerId);
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void cmsSigner(final int workerId) throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(workerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(workerId, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(workerId);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        testCase.signGenericDocument(workerId, "Sample data".getBytes());
    }
    
    private void setXMLSignerProperties(final int workerId) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.xmlsigner.XMLSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "XMLSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(workerId, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
    }
    
    private void setXMLSignerPropertiesReferingToken(final int workerId, final String tokenName, String alias) throws IOException {
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
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", tokenName);
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
            setXMLSignerProperties(workerId);
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
     * @throws Exception
     */
    @Test
    public void testXMLSigner_separateToken() throws Exception {
        LOG.info("testXMLSigner_separateToken");
        final int workerId = WORKER_XML2;
        final String alias = "xmlsignertestkey";
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setXMLSignerPropertiesReferingToken(workerId, CRYPTO_TOKEN_NAME, null);
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
        workerSession.uploadSignerCertificateChain(workerId, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
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
    
    private void setODFSignerProperties(final int workerId) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.odfsigner.ODFSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "ODFSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(workerId, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
    }
    
    /**
     * Tests setting up a ODF Signer, giving it a certificate and sign a document.
     */
    @Test
    public void testODFSigner_uncached() throws Exception {
        LOG.info("testODFSigner_uncached");
        final int workerId = WORKER_ODF;
        try {
            setODFSignerProperties(workerId);
            workerSession.reloadConfiguration(workerId);
            
            odfSigner(workerId);
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void odfSigner(final int workerId) throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(workerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(workerId, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(workerId);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        testCase.signGenericDocument(workerId, readFile(odfSampleFile));
    }
    
    private void setOOXMLSignerProperties(final int workerId) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.ooxmlsigner.OOXMLSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "OOXMLSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(workerId, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
    }
    
    /**
     * Tests setting up a OOXML Signer, giving it a certificate and sign a document.
     */
    @Test
    public void testOOXMLSigner_uncached() throws Exception {
        LOG.info("testOOXMLSigner_uncached");
        final int workerId = WORKER_OOXML;
        try {
            setOOXMLSignerProperties(workerId);
            workerSession.reloadConfiguration(workerId);
            ooxmlSigner(workerId);
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    private void ooxmlSigner(final int workerId) throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(workerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(workerId, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(workerId);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        testCase.signGenericDocument(workerId, readFile(ooxmlSampleFile));
    }

    private void setMSAuthTimeStampSignerProperties(final int workerId) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.tsa.MSAuthCodeTimeStampSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "MSAuthTSSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(workerId, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "DEFAULTTSAPOLICYOID", "1.2.3");
    }
    
    /**
     * Tests setting up a MSAuthCodeTimeStamp Signer, giving it a certificate and request a time-stamp token.
     */
    @Test
    public void testMSAuthTSSigner_uncached() throws Exception {
        LOG.info("testMSAuthTSSigner_uncached");
        final int workerId = WORKER_MSA;
        try {
            setMSAuthTimeStampSignerProperties(workerId);
            workerSession.reloadConfiguration(workerId);
            msauthTSSigner(workerId);
        } finally {
            testCase.removeWorker(workerId);
        }
    }
    
    private void msauthTSSigner(final int workerId) throws Exception {        
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(workerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(workerId, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(workerId);

        // Test active
        List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        GenericSignRequest signRequest = new GenericSignRequest(678, MSAUTHCODE_REQUEST_DATA.getBytes());
        final GenericSignResponse res = (GenericSignResponse) processSession.process(new WorkerIdentifier(workerId), signRequest, new RemoteRequestContext());
        Certificate signercert = res.getSignerCertificate();
        assertNotNull(signercert);

        byte[] buf = res.getProcessedData();
        CMSSignedData s = new CMSSignedData(Base64.decode(buf));

        int verified = 0;
        Store certStore = s.getCertificates();
        SignerInformationStore signers = s.getSignerInfos();
        Collection c = signers.getSigners();
        Iterator it = c.iterator();

        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation)it.next();
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
            
            cmsSigner(workerId);
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
     *
     * @throws Exception 
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
     * 
     * @throws Exception
     */
    @Test
    public void testNoSharedLibrary() throws Exception {
        LOG.info("testNoSharedLibrary");
        
        final int workerId = WORKER_XML;
        
        try {
            final String expectedPrefix =
                    "Failed to initialize crypto token: Missing SHAREDLIBRARYNAME property";
            setXMLSignerProperties(workerId);
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
            testCase.assertTrue("Should contain error: " + errors, foundError);
        } finally {
            testCase.removeWorker(workerId);
        }
    }
    
    /**
     * Test that setting a non-existing P11 shared library results
     * in a descriptive error reported by getFatalErrors().
     * 
     * @throws Exception
     */
    @Test
    public void testNonExistingSharedLibrary() throws Exception {
        LOG.info("testNonExistingSharedLibrary");
        
        final int workerId = WORKER_XML;
        
        try {
            final String expectedErrorPrefix =
                    "Failed to initialize crypto token: SHAREDLIBRARYNAME NonExistingLibrary is not referring to a defined value";
            setXMLSignerProperties(workerId);
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
            
            testCase.assertTrue("Should contain error about lib name but was: " + errors,
                        foundError);
        } finally {
            testCase.removeWorker(workerId);
        }
    }
    
    /**
     * Test that setting both the old and new property at the same time
     * is allowed for backwards compatability when pointing to the same
     * library.
     * 
     * @throws Exception 
     */
    @Test
    public void testBothP11LibraryNameAndOldSharedLibraryPropertyReferringSame() throws Exception {
        LOG.info("testBothP11LibraryNameAndOldSharedLibraryProperty");
        
        final int workerId = WORKER_XML;
        
        try {
            final String unexpectedErrorPrefix =
                    "Failed to initialize crypto token: Can not specify both SHAREDLIBRARY and SHAREDLIBRARYNAME at the same time";
            
            setXMLSignerProperties(workerId);
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
     * @throws java.lang.Exception
     */
    @Test
    public void testFatalErrorExistsWithDummyCertificate() throws Exception {
        LOG.info("testFatalErrorExistsWithDummyCertificate");
        final int workerId = WORKER_XML;
        try {

            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
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

            setXMLSignerPropertiesReferingToken(workerId, CRYPTO_TOKEN_NAME, TEST_KEY_ALIAS_2);
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
    
    private void cryptoTokenPropertiesHelper(final int crypoWokerId, final String signatureAlgorithm) throws Exception {
        // Setup token
        workerSession.setWorkerProperty(crypoWokerId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(crypoWokerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(crypoWokerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(crypoWokerId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(crypoWokerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(crypoWokerId, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(crypoWokerId, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(crypoWokerId, "PIN", pin);
        workerSession.setWorkerProperty(crypoWokerId, "DEFAULTKEY", existingKey1); // Test key 
        workerSession.setWorkerProperty(crypoWokerId, "SIGNATUREALGORITHM", signatureAlgorithm);
    }    
      
    private void testSigningWithProvidedSigAlgo(final String signatureAlgorithm) throws Exception {
        LOG.info(">testSigningWithProvidedSigAlgo(" + signatureAlgorithm + ")");
        try {
            cryptoTokenPropertiesHelper(CRYPTO_TOKEN, signatureAlgorithm);
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
     * 
     * @throws Exception
     */
    @Test
    public void testSign_SHA256withRSA_JackNJI11CryptoToken() throws Exception {
        LOG.info("testSign_SHA256withRSA_JackNJI11CryptoToken");
        testSigningWithProvidedSigAlgo("SHA256withRSA");
    }
    
    /**
     * Test signing by JackNJI11CryptoToken key with SHA512withRSA signature algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void testSign_SHA512withRSA_JackNJI11CryptoToken() throws Exception {
        LOG.info("testSign_SHA512withRSA_JackNJI11CryptoToken");
        testSigningWithProvidedSigAlgo("SHA512withRSA");
    }
    
    /**
     * Test signing by JackNJI11CryptoToken key with SHA256withRSAandMGF1 signature algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void testSign_SHA256withRSAandMGF1_JackNJI11CryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.PSS_SIGNATURE_ALGORITHM_SUPPORTED")));
        LOG.info("testSign_SHA256withRSAandMGF1_JackNJI11CryptoToken");
        testSigningWithProvidedSigAlgo("SHA256withRSAandMGF1");
    }
    
    /**
     * Test signing by JackNJI11CryptoToken key with SHA384withRSAandMGF1 signature algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void testSign_SHA384withRSAandMGF1_JackNJI11CryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.PSS_SIGNATURE_ALGORITHM_SUPPORTED")));
        LOG.info("testSign_SHA384withRSAandMGF1_JackNJI11CryptoToken");
        testSigningWithProvidedSigAlgo("SHA384withRSAandMGF1");
    }
    
    /**
     * Test signing by JackNJI11CryptoToken key with SHA512withRSAandMGF1 signature algorithm.
     * 
     * @throws Exception
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
            cryptoTokenPropertiesHelper(CRYPTO_TOKEN, "SHA256withRSA");
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
     * 
     * @throws Exception
     */
    @Test
    public void testSign_SHA256withRSA_KeyWrappingCryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.KEY_WRAPPING_UNWRAPPING_SUPPORTED")));
        LOG.info("testSign_SHA256withRSA_KeyWrappingCryptoToken");
        testSigningWithProvidedSigAlgo_KeyWrappingCryptoToken("SHA256withRSA");
    }
    
    /**
     * Test signing by JackNJI11KeyWrappingCryptoToken key with SHA512withRSA signature algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void testSign_SHA512withRSA_KeyWrappingCryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.KEY_WRAPPING_UNWRAPPING_SUPPORTED")));
        LOG.info("testSign_SHA512withRSA_KeyWrappingCryptoToken");
        testSigningWithProvidedSigAlgo_KeyWrappingCryptoToken("SHA512withRSA");
    }
    
    /**
     * Test signing by JackNJI11KeyWrappingCryptoToken key with SHA256withRSAandMGF1 signature algorithm.
     * 
     * @throws Exception
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
     * 
     * @throws Exception
     */
    @Test
    public void testSign_SHA512withRSAandMGF1_KeyWrappingCryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.KEY_WRAPPING_UNWRAPPING_SUPPORTED")));
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.PSS_SIGNATURE_ALGORITHM_SUPPORTED")));
        LOG.info("testSign_SHA512withRSAandMGF1_KeyWrappingCryptoToken");
        testSigningWithProvidedSigAlgo_KeyWrappingCryptoToken("SHA512withRSAandMGF1");
    }
    
    private void setUpPlainSigner() throws Exception {
        setPlainSignerProperties(WORKER_PLAIN_SIGNER);
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
        workerSession.uploadSignerCertificateChain(WORKER_PLAIN_SIGNER, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(WORKER_PLAIN_SIGNER);

    }
    
    private void setUpPlainSignerWithKeyWrappingCryptoToken() throws Exception {

        cryptoTokenPropertiesHelper(CRYPTO_TOKEN, "SHA256withRSA");
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

        setPlainSignerPropertiesWithKeyWrappingCryptoToken(WORKER_PLAIN_SIGNER);
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
        workerSession.uploadSignerCertificateChain(WORKER_PLAIN_SIGNER, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(WORKER_PLAIN_SIGNER);

    }
    
    private void setPlainSignerProperties(final int wokerId) throws Exception {
        // Setup token
        workerSession.setWorkerProperty(wokerId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(wokerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.PlainSigner");
        workerSession.setWorkerProperty(wokerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(wokerId, "NAME", TEST_PLAIN_SIGNER_NAME);
        workerSession.setWorkerProperty(wokerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(wokerId, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(wokerId, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(wokerId, "PIN", pin);
        workerSession.setWorkerProperty(wokerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(wokerId, "DEFAULTKEY", existingKey1); // Test key         
    }
    
    private void setPlainSignerPropertiesWithKeyWrappingCryptoToken(final int wokerId) throws Exception {
        // Setup token
        workerSession.setWorkerProperty(wokerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.PlainSigner");
        workerSession.setWorkerProperty(wokerId, "CRYPTOTOKEN", KEYWRAPPING_CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(wokerId, "NAME", TEST_PLAIN_SIGNER_NAME);
        workerSession.setWorkerProperty(wokerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(wokerId, "DEFAULTKEY", TEST_KEY_ALIAS_2);
    }
    
    private SimplifiedResponse sign_With_PlainSigner(final byte[] data, String signatureAlgorithm) throws Exception {
        try {
            setUpPlainSigner();
            workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "SIGNATUREALGORITHM", signatureAlgorithm);
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
    
    private SimplifiedResponse sign_With_PlainSigner_WrappedKey(final byte[] data, String signatureAlgorithm) throws Exception {
        try {
            setUpPlainSignerWithKeyWrappingCryptoToken();
            workerSession.setWorkerProperty(WORKER_PLAIN_SIGNER, "SIGNATUREALGORITHM", signatureAlgorithm);
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
     * 
     * @throws Exception 
     */
    @Test
    public void testNONESigning_RSA_SHA256_structure_JackNJI11CryptoToken() throws Exception {
        LOG.info("testNONESigning_RSA_SHA256_structure_JackNJI11CryptoToken");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plainText);
        byte[] hash = md.digest();

        // Taken from RFC 3447, page 42 for SHA-256, create input for signing
        byte[] modifierBytes = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(modifierBytes);
        baos.write(hash);

        SimplifiedResponse resp = sign_With_PlainSigner(baos.toByteArray(), "NONEwithRSA");
        assertSignedAndVerifiable(plainText, "SHA256withRSA", resp);
    }
    
    /**
     * Test that signing through wrapped key works and signature is verified when signature
     * algorithm is NONEwithRSA and input is SHA-256 hash digest.
     *
     * @throws Exception
     */
    @Test
    public void testNONESigning_RSA_SHA256_structure_JackNJI11KeyWrappingCryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.KEY_WRAPPING_UNWRAPPING_SUPPORTED")));

        LOG.info("testNONESigning_RSA_SHA256_structure_JackNJI11KeyWrappingCryptoToken");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plainText);
        byte[] hash = md.digest();

        // Taken from RFC 3447, page 42 for SHA-256, create input for signing
        byte[] modifierBytes = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(modifierBytes);
        baos.write(hash);

        SimplifiedResponse resp = sign_With_PlainSigner_WrappedKey(baos.toByteArray(), "NONEwithRSA");
        assertSignedAndVerifiable(plainText, "SHA256withRSA", resp);
    }
    
    /**
     * Test that signing works and signature is verified when signature algorithm is NONEwithRSA and input is SHA-512 hash digest.
     * 
     * @throws Exception 
     */
    @Test
    public void testNONESigning_RSA_SHA512_structure_JackNJI11CryptoToken() throws Exception {
        LOG.info("testNONESigning_RSA_SHA512_structure_JackNJI11CryptoToken");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(plainText);
        byte[] hash = md.digest();

        // Taken from RFC 3447, page 42 for SHA-512, create input for signing
        byte[] modifierBytes = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(modifierBytes);
        baos.write(hash);

        SimplifiedResponse resp = sign_With_PlainSigner(baos.toByteArray(), "NONEwithRSA");
        assertSignedAndVerifiable(plainText, "SHA512withRSA", resp);
    }
    
    /**
     * Test that signing through wrapped key works and signature is verified
     * when signature algorithm is NONEwithRSA and input is SHA-512 hash digest.
     *
     * @throws Exception
     */
    @Test
    public void testNONESigning_RSA_SHA512_structure_JackNJI11KeyWrappingCryptoToken() throws Exception {
        Assume.assumeTrue("true".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.KEY_WRAPPING_UNWRAPPING_SUPPORTED")));
        
        LOG.info("testNONESigning_RSA_SHA512_structure_JackNJI11KeyWrappingCryptoToken");
        // code example includes MessageDigest for the sake of completeness
        byte[] plainText = "some-data".getBytes("ASCII");
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(plainText);
        byte[] hash = md.digest();

        // Taken from RFC 3447, page 42 for SHA-512, create input for signing
        byte[] modifierBytes = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(modifierBytes);
        baos.write(hash);

        SimplifiedResponse resp = sign_With_PlainSigner_WrappedKey(baos.toByteArray(), "NONEwithRSA");
        assertSignedAndVerifiable(plainText, "SHA512withRSA", resp);
    }

}
