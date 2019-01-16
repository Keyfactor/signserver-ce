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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
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
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
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
public class P11SignTest extends ModulesTestCase {

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

    private final WorkerSession workerSession = getWorkerSession();
    private final ProcessSessionRemote processSession = getProcessSession();
    private final GlobalConfigurationSessionRemote globalSession = getGlobalSession();
    
    public P11SignTest() throws FileNotFoundException {
        final File home = PathUtil.getAppHome();
        pdfSampleFile = new File(home, "res/test/pdf/sample.pdf");
        odfSampleFile = new File(home, "res/test/test.odt");
        ooxmlSampleFile = new File(home, "res/test/test.docx");
        sharedLibraryName = getConfig().getProperty("test.p11.sharedLibraryName");
        sharedLibraryPath = getConfig().getProperty("test.p11.sharedLibraryPath");
        slot = getConfig().getProperty("test.p11.slot");
        pin = getConfig().getProperty("test.p11.pin");
        existingKey1 = getConfig().getProperty("test.p11.existingkey1");
    }
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
    }

    
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    private void setupCryptoTokenProperties(final int tokenId, final boolean cache) throws Exception {
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
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "PDFSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOT", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    /** Tests that the getCertificateRequest method generates a request. */
    public void testGenerateCSR() throws Exception {
        try {
            setPDFSignerWithCryptoProperties(WORKER_PDF, false);
            workerSession.reloadConfiguration(WORKER_PDF);
            
            // Tests generating a CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
            Base64SignerCertReqData csr = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
            assertNotNull(csr);
            assertNotNull(csr.getBase64CertReq());
            assertTrue(csr.getBase64CertReq().length > 0);
            
            // Test for an non-existing key label
            setPDFSignerWithCryptoProperties(WORKER_PDF, false);
            workerSession.setWorkerProperty(WORKER_PDF, "DEFAULTKEY", "NON-EXISTING-KEY-LABEL");
            workerSession.reloadConfiguration(WORKER_PDF);
            try {
                certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
                getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
                fail("Should have thrown exception as the DEFAULTKEY does not exist");
            } catch (CryptoTokenOfflineException ok) { // NOPMD
                // OK
            }
        } finally {
            removeWorker(WORKER_PDF);
        }
    }
    
    /** Tests that the getCertificateRequest method generates a request. */
    public void testGenerateCSR_separateToken() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            setPDFSignerOnlyProperties(WORKER_PDF);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(WORKER_PDF);

            // Tests generating a CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
            Base64SignerCertReqData csr = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
            assertNotNull(csr);
            assertNotNull(csr.getBase64CertReq());
            assertTrue(csr.getBase64CertReq().length > 0);

            // Test for an non-existing key label
            workerSession.setWorkerProperty(WORKER_PDF, "DEFAULTKEY", "NON-EXISTING-KEY-LABEL");
            workerSession.reloadConfiguration(WORKER_PDF);
            try {
                certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
                getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);
                fail("Should have thrown exception as the DEFAULTKEY does not exist");
            } catch (CryptoTokenOfflineException ok) { // NOPMD
                // OK
            }
        } finally {
            removeWorker(CRYPTO_TOKEN);
            removeWorker(WORKER_PDF);
        }
    }

    /**
     * Tests setting up a PDF Signer, giving it a certificate and sign a document.
     */
    public void testPDFSigner_uncached() throws Exception {
        try {
            setPDFSignerWithCryptoProperties(WORKER_PDF, false);
            workerSession.reloadConfiguration(WORKER_PDF);
            
            pdfSignerTest();
        } finally {
            removeWorker(WORKER_PDF);
        }
    }

    /**
     * Tests setting up a PDF Signer, giving it a certificate and sign a document.
     */
    public void testPDFSigner_uncached_separateToken() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            setPDFSignerOnlyProperties(WORKER_PDF);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(WORKER_PDF);

            pdfSignerTest();
        } finally {
            removeWorker(CRYPTO_TOKEN);
            removeWorker(WORKER_PDF);
        }
    }

    /**
     * Tests setting up a PDF Signer, giving it a certificate and sign a document.
     */
    public void testPDFSigner_cached() throws Exception {
        try {
            setPDFSignerWithCryptoProperties(WORKER_PDF, true);
            workerSession.reloadConfiguration(WORKER_PDF);
            
            pdfSignerTest();
        } finally {
            removeWorker(WORKER_PDF);
        }
    }

    /**
     * Tests setting up a PDF Signer, giving it a certificate and sign a document.
     */
    public void testPDFSigner_cached_separateToken() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, true);
            setPDFSignerOnlyProperties(WORKER_PDF);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(WORKER_PDF);

            pdfSignerTest();
        } finally {
            removeWorker(CRYPTO_TOKEN);
            removeWorker(WORKER_PDF);
        }
    }
    
    private void pdfSignerTest() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_PDF), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
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
        signGenericDocument(WORKER_PDF, readFile(pdfSampleFile));
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
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "TSSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOT", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "DEFAULTTSAPOLICYOID", "1.2.3");
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
        workerSession.setWorkerProperty(workerId, "ACCEPTANYPOLICY", "true");
        
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
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
     * Test that key usage counter increments as expected for TimeStampSigner
     * then the certificate is uploaded to the signer configuration.
     * 
     * @throws Exception 
     */
    public void testTSSigner_keyUsageCounterCertInConfig() throws Exception {
        testTSSigner_keyUsageCounter(true);
    }
    
    /**
     * Test that key usage counter increments as expected for TimeStampSigner
     * then the certificate is uploaded to the token.
     * 
     * @throws Exception 
     */
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
            Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_TSA_ALTKEY), certReqInfo, false);

            // Issue certificate
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
            KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
            X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo())
                    .addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping).toASN1Primitive())
                    .build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

            // Install certificate and chain
            if (certInConfig) {
                workerSession.uploadSignerCertificate(WORKER_TSA_ALTKEY, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
                workerSession.uploadSignerCertificateChain(WORKER_TSA_ALTKEY, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            } else {
                workerSession.importCertificateChain(new WorkerIdentifier(WORKER_TSA_ALTKEY),
                                                     Arrays.asList(cert.getEncoded()),
                                                     key, pin.toCharArray());
            }
            workerSession.reloadConfiguration(WORKER_TSA_ALTKEY);
            
            final long keyUsageBefore = workerSession.getKeyUsageCounterValue(new WorkerIdentifier(WORKER_TSA_ALTKEY));
            
            // Test signing
            TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
            TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
            byte[] requestBytes = timeStampRequest.getEncoded();
            GenericSignRequest signRequest = new GenericSignRequest(567, requestBytes);
            final GenericSignResponse res = (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_TSA_ALTKEY), signRequest, new RemoteRequestContext());
            Certificate signercert = res.getSignerCertificate();
            assertNotNull(signercert);
            final TimeStampResponse timeStampResponse = new TimeStampResponse((byte[]) res.getProcessedData());
            timeStampResponse.validate(timeStampRequest);

            assertEquals("Token granted", PKIStatus.GRANTED, timeStampResponse.getStatus());
            assertNotNull("Got timestamp token", timeStampResponse.getTimeStampToken());
            
            assertEquals("Key used once", keyUsageBefore + 1, workerSession.getKeyUsageCounterValue(new WorkerIdentifier(WORKER_TSA_ALTKEY)));
            
        } finally {
            workerSession.removeKey(new WorkerIdentifier(WORKER_TSA_ALTKEY), key);
            removeWorker(WORKER_TSA_ALTKEY);
        }
    }
    
    
    /**
     * Tests setting up a TimeStamp Signer, giving it a certificate and request a time-stamp token.
     */
    public void testTSSigner_uncached() throws Exception {
        try {
            setTimeStampSignerProperties(WORKER_TSA, false);
            workerSession.reloadConfiguration(WORKER_TSA);
            tsSigner();
        } finally {
            removeWorker(WORKER_TSA);
        }
    }
    
    public void testTSSigner_cached() throws Exception {
        try {
            setTimeStampSignerProperties(WORKER_TSA, true);
            workerSession.reloadConfiguration(WORKER_TSA);
            tsSigner();
        } finally {
            removeWorker(WORKER_TSA);
        }
    }
    
    private void tsSigner() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_TSA, null);
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(new WorkerIdentifier(WORKER_TSA), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
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
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "SODSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOT", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }
    
    /**
     * Tests setting up a MRTD SOD Signer, giving it a certificate and requests an SOd.
     */
    public void testMRTDSODSigner_uncached() throws Exception {
        final int workerId = WORKER_SOD;
        try {
            setMRTDSODSignerProperties(workerId, false);
            workerSession.reloadConfiguration(workerId);
            
            mrtdsodSigner(workerId);
        } finally {
            removeWorker(workerId);
        }
    }
    
    public void testMRTDSODSigner_cached() throws Exception {
        final int workerId = WORKER_SOD;
        try {
            setMRTDSODSignerProperties(workerId, true);
            workerSession.reloadConfiguration(workerId);
            
            mrtdsodSigner(workerId);
        } finally {
            removeWorker(workerId);
        }
    }
    
    private void mrtdsodSigner(final int workerId) throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
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
    
    private void setCMSSignerProperties(final int workerId, final boolean cached) throws IOException {
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
    public void testCMSSigner_uncached() throws Exception {
        final int workerId = WORKER_CMS;
        try {
            setCMSSignerProperties(workerId, false);
            workerSession.reloadConfiguration(workerId);
            
            cmsSigner(workerId);
        } finally {
            removeWorker(workerId);
        }
    }
    
    public void testCMSSigner_cached() throws Exception {
        final int workerId = WORKER_CMS;
        try {
            setCMSSignerProperties(workerId, true);
            workerSession.reloadConfiguration(workerId);
            
            cmsSigner(workerId);
        } finally {
            removeWorker(workerId);
        }
    }
    
    private void cmsSigner(final int workerId) throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
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
        signGenericDocument(workerId, "Sample data".getBytes());
    }
    
    private void setXMLSignerProperties(final int workerId, final boolean cache) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.xmlsigner.XMLSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "XMLSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOT", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }

    private void setXMLSignerPropertiesReferingToken(final int workerId, final String tokenName, final boolean cache) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.xmlsigner.XMLSigner");
        workerSession.setWorkerProperty(workerId, "NAME", "XMLSignerRefering");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", tokenName);
    }

    /**
     * Tests setting up a XML Signer, giving it a certificate and sign a document.
     */
    public void testXMLSigner_uncached() throws Exception {
        final int workerId = WORKER_XML;
        try {
            setXMLSignerProperties(workerId, false);
            workerSession.reloadConfiguration(workerId);
            
            xmlSigner(workerId);
        } finally {
            removeWorker(workerId);
        }
    }
    
    public void testXMLSigner_cached() throws Exception {
        final int workerId = WORKER_XML;
        try {
            setXMLSignerProperties(workerId, true);
            workerSession.reloadConfiguration(workerId);
            
            xmlSigner(workerId);
        } finally {
            removeWorker(workerId);
        }
    }

    /**
     * Exercises a signer using a separate token and where the private key is
     * cached (in the worker).
     * @throws Exception
     */
    public void testXMLSigner_cached_separateToken() throws Exception {
        final int workerId = WORKER_XML2;
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, false);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            setXMLSignerPropertiesReferingToken(workerId, CRYPTO_TOKEN_NAME, true);
            workerSession.reloadConfiguration(workerId);

            xmlSigner(workerId);
        } finally {
            removeWorker(workerId);
        }
    }

    private void xmlSigner(final int workerId) throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
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
        signGenericDocument(workerId, "<sampledata/>".getBytes());

        // Test removing the DEFAULTKEY property, should result in a CryptoTokenOfflineException
        workerSession.removeWorkerProperty(workerId, "DEFAULTKEY");
        workerSession.reloadConfiguration(workerId);

        try {
            signGenericDocument(workerId, "<sampledata/>".getBytes());
            fail("Should throw a CryptoTokenOfflineException");
        } catch (CryptoTokenOfflineException e) {
            // expected
        }
    }
    
    private void setODFSignerProperties(final int workerId, final boolean cache) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.odfsigner.ODFSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "ODFSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOT", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }
    
    /**
     * Tests setting up a ODF Signer, giving it a certificate and sign a document.
     */
    public void testODFSigner_uncached() throws Exception {
        final int workerId = WORKER_ODF;
        try {
            setODFSignerProperties(workerId, false);
            workerSession.reloadConfiguration(workerId);
            
            odfSigner(workerId);
        } finally {
            removeWorker(workerId);
        }
    }
    
    public void testODFSigner_cached() throws Exception {
        final int workerId = WORKER_ODF;
        try {
            setODFSignerProperties(workerId, true);
            workerSession.reloadConfiguration(workerId);
            
            odfSigner(workerId);
        } finally {
            removeWorker(workerId);
        }
    }
    
    private void odfSigner(final int workerId) throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
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
        signGenericDocument(workerId, readFile(odfSampleFile));
    }
    
    private void setOOXMLSignerProperties(final int workerId, final boolean cache) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.ooxmlsigner.OOXMLSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "OOXMLSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOT", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }
    
    /**
     * Tests setting up a OOXML Signer, giving it a certificate and sign a document.
     */
    public void testOOXMLSigner_uncached() throws Exception {
        final int workerId = WORKER_OOXML;
        try {
            setOOXMLSignerProperties(workerId, false);
            workerSession.reloadConfiguration(workerId);
            ooxmlSigner(workerId);
        } finally {
            removeWorker(workerId);
        }
    }
    
    public void testOOXMLSigner_cached() throws Exception {
        final int workerId = WORKER_OOXML;
        try {
            setOOXMLSignerProperties(workerId, true);
            workerSession.reloadConfiguration(workerId);
            ooxmlSigner(workerId);
        } finally {
            removeWorker(workerId);
        }
    }
    
    private void ooxmlSigner(final int workerId) throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
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
        signGenericDocument(workerId, readFile(ooxmlSampleFile));
    }

    private void setMSAuthTimeStampSignerProperties(final int workerId, final boolean cache) throws IOException {
        // Setup worker
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.tsa.MSAuthCodeTimeStampSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "MSAuthTSSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(workerId, "SLOT", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "DEFAULTTSAPOLICYOID", "1.2.3");
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }
    
    /**
     * Tests setting up a MSAuthCodeTimeStamp Signer, giving it a certificate and request a time-stamp token.
     */
    public void testMSAuthTSSigner_uncached() throws Exception {
        final int workerId = WORKER_MSA;
        try {
            setMSAuthTimeStampSignerProperties(workerId, false);
            workerSession.reloadConfiguration(workerId);
            msauthTSSigner(workerId);
        } finally {
            removeWorker(workerId);
        }
    }
    
    public void testMSAuthTSSigner_cached() throws Exception {
        final int workerId = WORKER_MSA;
        try {
            setMSAuthTimeStampSignerProperties(workerId, true);
            workerSession.reloadConfiguration(workerId);
            msauthTSSigner(workerId);
        } finally {
            removeWorker(workerId);
        }
    }
    
    private void msauthTSSigner(final int workerId) throws Exception {        
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
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
     * Test having default PKCS11CryptoToken properties.
     * Tests setting up a CMS Signer, giving it a certificate and sign a file.
     */
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
            
            cmsSigner(workerId);
        } finally {
            removeWorker(workerId);
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
            removeWorker(workerId);
        }
    }
    
    /**
     * Tests key generation when requesting a custom DN for the self-signed
     * certificate.
     *
     * @throws Exception 
     */
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
            removeWorker(workerId);
        }
    }
    
    /**
     * Test that generating a key with a specified key spec results in the
     * expected public exponent on the public key.
     * 
     * @param spec
     * @param expected
     * @throws Exception 
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
            Base64SignerCertReqData data = (Base64SignerCertReqData) workerSession
                .getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false, "keywithexponent");
            final byte[] reqBytes = data.getBase64CertReq();
            final PKCS10CertificationRequest req
                = new PKCS10CertificationRequest(Base64.decode(reqBytes));

            final RSAPublicKey pubKey = (RSAPublicKey) getPublicKeyFromRequest(req);
            
            assertEquals("Returned public exponent",
                         expected, pubKey.getPublicExponent());
        } finally {
            try {
                workerSession.removeKey(new WorkerIdentifier(workerId), "keywithexponent");
            } catch (SignServerException ignored) {}
            removeWorker(workerId);
        }
    }
    
    /**
     * Test generating a key with a custom specified public exponent in the spec.
     *
     * @throws Exception 
     */
    public void testGenerateKeyWithPublicExponentCustom() throws Exception {
        testGenerateKeyWithPublicExponent("2048 exp 5", BigInteger.valueOf(5));
    }
    
    /**
     * Test generateing a key with the default public exponent.
     * 
     * @throws Exception 
     */
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
            removeWorker(workerId);
        }
    }

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
            removeWorker(tokenId);
        }
    }
    
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
            removeWorker(workerId);
        }
    }

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
            removeWorker(tokenId);
        }
    }

    /**
     * Test that missing the SHAREDLIBRARY property results
     * in a descriptive error reported by getFatalErrors().
     * 
     * @throws Exception
     */
    public void testNoSharedLibrary() throws Exception {
        LOG.info("testNoSharedLibrary");
        
        final int workerId = WORKER_XML;
        
        try {
            final String expectedPrefix =
                    "Failed to initialize crypto token: Missing SHAREDLIBRARYNAME property";
            setXMLSignerProperties(workerId, false);
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
            removeWorker(workerId);
        }
    }
    
    /**
     * Test that setting a non-existing P11 shared library results
     * in a descriptive error reported by getFatalErrors().
     * 
     * @throws Exception
     */
    public void testNonExistingSharedLibrary() throws Exception {
        LOG.info("testNonExistingSharedLibrary");
        
        final int workerId = WORKER_XML;
        
        try {
            final String expectedErrorPrefix =
                    "Failed to initialize crypto token: SHAREDLIBRARYNAME NonExistingLibrary is not referring to a defined value";
            setXMLSignerProperties(workerId, false);
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
            removeWorker(workerId);
        }
    }
    
    /**
     * Test that specifying the old property SHAREDLIBRARY not pointing to
     * a value defined in the P11 library list will give a deprecation error.
     */
    public void testOldSharedLibraryPropertyPointingToUndefined() throws Exception {
        LOG.info("testOldSharedLibraryPropertyPointingToUndefined");
        
        final int workerId = WORKER_XML;
        
        try {
            final String expectedErrorPrefix =
                    "Failed to initialize crypto token: SHAREDLIBRARY is not permitted when pointing to a library not defined at deploy-time";
            setXMLSignerProperties(workerId, false);
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
            assertTrue("Should contain error about lib name but was: " + errors,
                    foundError);
        } finally {
            removeWorker(workerId);
        }
    }
    
    /**
     * Test that specifying the old property SHAREDLIBRARY pointing to a library
     * defined in deploy-time works.
     * 
     * @throws Exception 
     */
    public void testOldSharedLibraryPropertyPointingToDefined() throws Exception {
        LOG.info("testOldSharedLibraryPropertyPointingToDefined");
        
        final int workerId = WORKER_XML;
        
        try {
            final String unexpectedErrorPrefix =
                    "Failed to initialize crypto token: SHAREDLIBRARY is not permitted when pointing to a library not defined at deploy-time";
            
            setXMLSignerProperties(workerId, false);
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
            removeWorker(workerId);
        }
    }
    
    /**
     * Test that setting both the old and new property at the same time
     * is not allowed when referring to different libraries.
     * 
     * @throws Exception 
     */
    public void testBothP11LibraryNameAndOldSharedLibraryProperty() throws Exception {
        LOG.info("testBothP11LibraryNameAndOldSharedLibraryProperty");
        
        final int workerId = WORKER_XML;
        
        try {
            final String expectedErrorPrefix =
                    "Failed to initialize crypto token: Can not specify both SHAREDLIBRARY and SHAREDLIBRARYNAME at the same time";
            
            setXMLSignerProperties(workerId, false);
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
            removeWorker(workerId);
        }
    }
    
    /**
     * Test that setting both the old and new property at the same time
     * is allowed for backwards compatability when pointing to the same
     * library.
     * 
     * @throws Exception 
     */
    public void testBothP11LibraryNameAndOldSharedLibraryPropertyReferringSame() throws Exception {
        LOG.info("testBothP11LibraryNameAndOldSharedLibraryProperty");
        
        final int workerId = WORKER_XML;
        
        try {
            final String unexpectedErrorPrefix =
                    "Failed to initialize crypto token: Can not specify both SHAREDLIBRARY and SHAREDLIBRARYNAME at the same time";
            
            setXMLSignerProperties(workerId, false);
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
            removeWorker(workerId);
        }
    }
}
