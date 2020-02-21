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
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
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
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.TokenOutOfSpaceException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Test signing with all signers using an AzureKeyVaultCryptoToken.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class AzureKeyVaultCryptoTokenSignTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AzureKeyVaultCryptoTokenSignTest.class);
    
    private static final int CRYPTO_TOKEN = 20100;
    private static final int WORKER_PDF = 20000;
    private static final int WORKER_TSA = 20001;
    private static final int WORKER_CMS = 20003;
    private static final int WORKER_MSA = 20007;
    
    private static final String MSAUTHCODE_REQUEST_DATA =
    		"MIIBIwYKKwYBBAGCNwMCATCCARMGCSqGSIb3DQEHAaCCAQQEggEAVVSpOKf9zJYc" +
    		"tyvqgeHfO9JkobPYihUZcW9TbYzAUiJGEsElNCnLUaO0+MZG0TS7hlzqKKvrdXc7" +
    		"O/8C7c8YyjYF5YrLiaYS8cw3VbaQ2M1NWsLGzxF1pxsR9sMDJvfrryPaWj4eTi3Y" +
    		"UqRNS+GTa4quX4xbmB0KqMpCtrvuk4S9cgaJGwxmSE7N3omzvERTUxp7nVSHtms5" +
    		"lVMb082JFlABT1/o2mL5O6qFG119JeuS1+ZiL1AEy//gRs556OE1TB9UEQU2bFUm" +
    		"zBD4VHvkOOB/7X944v9lmK5y9sFv+vnf/34catL1A+ZNLwtd1Qq2VirqJxRK/T61" +
    		"QoSWj4rGpw==";
    
    /* alias prefix to use when creating new keys, a timestamp is added to
     * avoid collisions with purged key names in case "soft deletion" is enabled
     * on the key vault.
     */
    private static final String TEST_KEY_ALIAS_PREFIX = "key";
    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenAzureKeyVault";

    private final String keyVaultName;
    private final String keyVaultClientId;
    private final String keyVaultType;
    private final String pin;
    private final String existingKey1;
    
    private final File pdfSampleFile;

    private final ModulesTestCase testCase = new ModulesTestCase();

    private final WorkerSession workerSession = testCase.getWorkerSession();
    private final ProcessSessionRemote processSession = testCase.getProcessSession();

    public AzureKeyVaultCryptoTokenSignTest() throws FileNotFoundException {
        final File home = PathUtil.getAppHome();
        pdfSampleFile = new File(home, "res/test/pdf/sample.pdf");
        keyVaultName = testCase.getConfig().getProperty("test.azurekeyvault.name");
        keyVaultClientId = testCase.getConfig().getProperty("test.azurekeyvault.clientid");
        keyVaultType = testCase.getConfig().getProperty("test.azurekeyvault.type");
        pin = testCase.getConfig().getProperty("test.azurekeyvault.pin");
        existingKey1 = testCase.getConfig().getProperty("test.azurekeyvault.existingkey1");
    }

    @Before
    public void setUp() throws Exception {
        final boolean enabled =
                Boolean.TRUE.toString().equalsIgnoreCase(testCase.getConfig().getProperty("test.azurekeyvault.enabled"));
        Assume.assumeTrue("Assumes test.azurekeyvault.enabled in test-config.properties",
                          enabled);
        SignServerUtil.installBCProvider();
    }

    private void setupCryptoTokenProperties(final int tokenId, final boolean cache) throws Exception {
        // Setup token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, AzureKeyVaultCryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "KEY_VAULT_NAME", keyVaultName);
        workerSession.setWorkerProperty(tokenId, "KEY_VAULT_CLIENT_ID",
                                        keyVaultClientId);
        workerSession.setWorkerProperty(tokenId, "KEY_VAULT_TYPE", keyVaultType);
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1); // Test key
        workerSession.setWorkerProperty(tokenId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    private void setPDFSignerOnlyProperties(final int workerId) throws Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.pdfsigner.PDFSigner");
        workerSession.setWorkerProperty(workerId, "NAME", "PDFSignerAzure");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
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
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA256WithRSA", "CN=Worker" + WORKER_PDF, null);
            AbstractCertReqData csr = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
            assertNotNull(csr);
            assertNotNull(csr.toBinaryForm());
            testCase.assertTrue(csr.toBinaryForm().length > 0);

            // Test for an non-existing key label
            workerSession.setWorkerProperty(WORKER_PDF, "DEFAULTKEY", "NON-EXISTING-KEY-LABEL");
            workerSession.reloadConfiguration(WORKER_PDF);
            try {
                certReqInfo = new PKCS10CertReqInfo("SHA256WithRSA", "CN=Worker" + WORKER_PDF, null);
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
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA256withRSA", "CN=Worker" + WORKER_PDF, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestAzure Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

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
    
    private void setTimeStampSignerProperties(final int workerId) throws IOException, CryptoTokenOfflineException, InvalidWorkerIdException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, OperatorCreationException, Exception {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.tsa.TimeStampSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, AzureKeyVaultCryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "TSSignerAzure");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "KEY_VAULT_NAME", keyVaultName);
        workerSession.setWorkerProperty(workerId, "KEY_VAULT_CLIENT_ID",
                                        keyVaultClientId);
        workerSession.setWorkerProperty(workerId, "KEY_VAULT_TYPE", keyVaultType);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "DEFAULTTSAPOLICYOID", "1.2.3");
        workerSession.setWorkerProperty(workerId, "ACCEPTANYPOLICY", "true");
        
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA256WithRSA", "CN=Worker" + workerId, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestAzure Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo())
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
    public void testTSSigner() throws Exception {
        LOG.info("testTSSigner_uncached");
        try {
            setTimeStampSignerProperties(WORKER_TSA);
            workerSession.reloadConfiguration(WORKER_TSA);
            tsSigner();
        } finally {
            testCase.removeWorker(WORKER_TSA);
        }
    }
    
    private void tsSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA256WithRSA", "CN=Worker" + WORKER_TSA, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_TSA), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestAzure Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).addExtension(org.bouncycastle.asn1.x509.X509Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

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
    
    private void setCMSSignerProperties(final int workerId) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.CMSSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, AzureKeyVaultCryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "CMSSignerAzure");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "KEY_VAULT_NAME", keyVaultName);
        workerSession.setWorkerProperty(workerId, "KEY_VAULT_CLIENT_ID",
                                        keyVaultClientId);
        workerSession.setWorkerProperty(workerId, "KEY_VAULT_TYPE", keyVaultType);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
    }
    
    /**
     * Tests setting up a CMS Signer, giving it a certificate and sign a file.
     */
    @Test
    public void testCMSSigner() throws Exception {
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
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA256WithRSA", "CN=Worker" + workerId, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestAzure Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

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

    private void setMSAuthTimeStampSignerProperties(final int workerId) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.tsa.MSAuthCodeTimeStampSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, AzureKeyVaultCryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "MSAuthTSSignerAzure");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "KEY_VAULT_NAME", keyVaultName);
        workerSession.setWorkerProperty(workerId, "KEY_VAULT_CLIENT_ID",
                                        keyVaultClientId);
        workerSession.setWorkerProperty(workerId, "KEY_VAULT_TYPE", keyVaultType);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "DEFAULTTSAPOLICYOID", "1.2.3");
    }
    
    /**
     * Tests setting up a MSAuthCodeTimeStamp Signer, giving it a certificate and request a time-stamp token.
     */
    @Test
    public void testMSAuthTSSigner() throws Exception {
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
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA256WithRSA", "CN=Worker" + workerId, null);
        AbstractCertReqData reqData = (AbstractCertReqData) testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestAzure Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

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
    
    private Set<String> getKeyAliases(final int workerId) throws Exception {
        Collection<KeyTestResult> testResults = workerSession.testKey(new WorkerIdentifier(workerId), "all", pin.toCharArray());
        final HashSet<String> results = new HashSet<>();
        for (KeyTestResult testResult : testResults) {
            results.add(testResult.getAlias());
        }
        return results;
    }
    
    /**
     * Test generating a new key.
     * 
     * NOTE: make sure to disable the "soft key delete" functionallity
     * on the test key vault to avoid creating too many purged keys remaining
     * in the vault.
     * 
     * @throws Exception 
     */
    @Test
    public void testGenerateKey() throws Exception {
        LOG.info("testGenerateKey");
        
        final int workerId = WORKER_CMS;
        final String alias = TEST_KEY_ALIAS_PREFIX +
                             Long.toString(System.currentTimeMillis());

        try {
            setCMSSignerProperties(workerId);
            workerSession.reloadConfiguration(workerId);

            // Generate a testkey
            
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "2048", alias, pin.toCharArray());
            
            // Check that the new alias is listed
            Set<String> aliases = getKeyAliases(workerId);
            assertTrue("new key added", aliases.contains(alias));
        } finally {
            try {
                workerSession.removeKey(new WorkerIdentifier(workerId), alias);
            } catch (SignServerException ignored) {}
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Tests that key generation is not allowed when the number of keys has
     * reached the KEYGENERATIONLIMIT.
     * Also checks that when allowing for one more keys, the next key can be
     * generated.
     * NOTE: make sure to disable the "soft key delete" functionallity
     * on the test key vault to avoid creating too many purged keys remaining
     * in the vault.
     */
    @SuppressWarnings("ThrowableResultIgnored")
    @Test
    public void testKeyGenerationLimit() throws Exception {
        LOG.info("testKeyGenerationLimit");
        
        final int workerId = WORKER_CMS;
        final String alias = TEST_KEY_ALIAS_PREFIX +
                             Long.toString(System.currentTimeMillis());

        try {
            setCMSSignerProperties(workerId);
            workerSession.reloadConfiguration(workerId);
            
            // Add a reference key
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "2048", alias, pin.toCharArray());
            
            // Check available aliases
            final int keys = getKeyAliases(workerId).size();
            
            // Set the current number of keys as maximum
            workerSession.setWorkerProperty(workerId, "KEYGENERATIONLIMIT", String.valueOf(keys));
            workerSession.reloadConfiguration(workerId);
            
            // Key generation should fail
            try {
                workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "2048", alias + "-additional", pin.toCharArray());
                fail("Should have failed because of no space in token");
            } catch (TokenOutOfSpaceException expected) { // NOPMD
                // OK
            }
            
            // Allow for one more keys to be created
            workerSession.setWorkerProperty(workerId, "KEYGENERATIONLIMIT", String.valueOf(keys + 1));
            workerSession.reloadConfiguration(workerId);
            
            // Generate a new key
            try {
                workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "2048", alias + "-additional", pin.toCharArray());
            } catch (CryptoTokenOfflineException ex) {
                fail("Should have worked but got: " + ex.getLocalizedMessage());
            }
            
            final int keys2 = getKeyAliases(workerId).size();
            assertEquals("one more key", keys + 1, keys2);
            
            // Key generation should fail
            try {
                workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "2048", alias + "-another", pin.toCharArray());
                fail("Should have failed because of no space in token");
            } catch (TokenOutOfSpaceException expected) { // NOPMD
                // OK
            }
        } finally {
            try {
                workerSession.removeKey(new WorkerIdentifier(workerId), alias);
            } catch (SignServerException ignored) {}
            try {
                workerSession.removeKey(new WorkerIdentifier(workerId), alias + "-additional");
            } catch (SignServerException ignored) {}
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Test generating a new key using a separate token.
     * 
     * NOTE: make sure to disable the "soft key delete" functionallity
     * on the test key vault to avoid creating too many purged keys remaining
     * in the vault.
     * 
     * @throws Exception 
     */
    @Test
    public void testGenerateKey_separateToken() throws Exception {
        LOG.info("testGenerateKey_separateToken");

        final int tokenId = CRYPTO_TOKEN;
        final String alias = TEST_KEY_ALIAS_PREFIX +
                             Long.toString(System.currentTimeMillis());

        try {
            setupCryptoTokenProperties(tokenId, false);
            workerSession.reloadConfiguration(tokenId);

            // Generate a testkey
            workerSession.generateSignerKey(new WorkerIdentifier(tokenId), "RSA", "2048", alias, pin.toCharArray());

            // Now expect the new TEST_KEY_ALIAS
            Set<String> aliases = getKeyAliases(tokenId);
            assertTrue("new key added", aliases.contains(alias));

        } finally {
            try {
                workerSession.removeKey(new WorkerIdentifier(tokenId), alias);
            } catch (SignServerException ignored) {}
            testCase.removeWorker(tokenId);
        }
    }
    
    /**
     * Test generating a new key and removing that key afterwards to check
     * that the key is longer listed.
     *
     * NOTE: make sure to disable the "soft key delete" functionallity
     * on the test key vault to avoid creating too many purged keys remaining
     * in the vault.
     * 
     * @throws Exception 
     */
    @Test
    public void testRemoveKey() throws Exception {
        LOG.info("testRemoveKey");
        
        final int workerId = WORKER_CMS;
        final String alias = TEST_KEY_ALIAS_PREFIX +
                             Long.toString(System.currentTimeMillis());

        try {
            setCMSSignerProperties(workerId);
            workerSession.reloadConfiguration(workerId);
            

            // Generate a testkey
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "2048", alias, pin.toCharArray());
            Set<String> aliases = getKeyAliases(workerId);

            if (!aliases.contains(alias)) {
                throw new Exception("Pre-condition failed: Key with alias " + alias + " could not be created");
            }
            
            // Remove the key
            workerSession.removeKey(new WorkerIdentifier(workerId), alias);
            
            // Now expect the TEST_KEY_ALIAS to have been removed
            Set<String> aliases2 = getKeyAliases(workerId);
            assertFalse("new key removed", aliases2.contains(alias));
        } finally {
            testCase.removeWorker(workerId);
        }
    }

    /**
     * Test generating a new key and removing that key afterwards to check
     * that the key is longer listed, using a separate token.
     *
     * NOTE: make sure to disable the "soft key delete" functionallity
     * on the test key vault to avoid creating too many purged keys remaining
     * in the vault.
     * 
     * @throws Exception 
     */
    @Test
    public void testRemoveKey_separateToken() throws Exception {
        LOG.info("testRemoveKey_separateToken");

        final int tokenId = CRYPTO_TOKEN;
        final String alias = TEST_KEY_ALIAS_PREFIX +
                             Long.toString(System.currentTimeMillis());

        try {
            setCMSSignerProperties(tokenId);
            workerSession.reloadConfiguration(tokenId);

            // Generate a testkey
            workerSession.generateSignerKey(new WorkerIdentifier(tokenId), "RSA", "2048", alias, pin.toCharArray());
            final Set<String> aliases1 = getKeyAliases(tokenId);

            if (!aliases1.contains(alias)) {
                throw new Exception("Pre-condition failed: Key with alias " + alias + " could not be created");
            }

            // Remove the key
            workerSession.removeKey(new WorkerIdentifier(tokenId), alias);

            // Now expect the TEST_KEY_ALIAS to have been removed
            Set<String> aliases2 = getKeyAliases(tokenId);
            Set<String> expected = new HashSet<>(aliases1);
            expected.remove(alias);
            assertEquals("new key removed", expected, aliases2);
        } finally {
            testCase.removeWorker(tokenId);
        }
    }

    private void cryptoTokenPropertiesHelper(final int cryptoWorkerId, final String signatureAlgorithm) throws Exception {
        // Setup token
        workerSession.setWorkerProperty(cryptoWorkerId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(cryptoWorkerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(cryptoWorkerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, AzureKeyVaultCryptoToken.class.getName());
        workerSession.setWorkerProperty(cryptoWorkerId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(cryptoWorkerId, "KEY_VAULT_NAME", keyVaultName);
        workerSession.setWorkerProperty(cryptoWorkerId, "KEY_VAULT_CLIENT_ID",
                                        keyVaultClientId);
        workerSession.setWorkerProperty(cryptoWorkerId, "KEY_VAULT_TYPE", keyVaultType);
        workerSession.setWorkerProperty(cryptoWorkerId, "PIN", pin);
        workerSession.setWorkerProperty(cryptoWorkerId, "DEFAULTKEY", existingKey1); // Test key 
        workerSession.setWorkerProperty(cryptoWorkerId, "SIGNATUREALGORITHM", signatureAlgorithm);
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
     * Test signing by AzureKeyVaultCryptoToken key with SHA256withRSA signature algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void testSign_SHA256withRSA_AzureKeyVaultCryptoToken() throws Exception {
        LOG.info("testSign_SHA256withRSA_AzureKeyVaultCryptoToken");
        testSigningWithProvidedSigAlgo("SHA256withRSA");
    }
    
    /**
     * Test signing by AzureKeyVaultCryptoToken key with SHA512withRSA signature algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void testSign_SHA512withRSA_AzureKeyVaultCryptoToken() throws Exception {
        LOG.info("testSign_SHA512withRSA_AzureKeyVaultCryptoToken");
        testSigningWithProvidedSigAlgo("SHA512withRSA");
    }
}
