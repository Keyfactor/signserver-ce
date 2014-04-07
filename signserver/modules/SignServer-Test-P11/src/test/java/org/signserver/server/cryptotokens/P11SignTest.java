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
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.fail;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
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
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.KeyTestResult;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.RequestContext;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
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
    
    private static final int WORKER_PDF = 20000;
    private static final int WORKER_TSA = 20001;
    private static final int WORKER_SOD = 20002;
    private static final int WORKER_CMS = 20003;
    private static final int WORKER_XML = 20004;
    private static final int WORKER_ODF = 20005;
    private static final int WORKER_OOXML = 20006;
    private static final int WORKER_MSA = 20007;
    
    private static final String MSAUTHCODE_REQUEST_DATA =
    		"MIIBIwYKKwYBBAGCNwMCATCCARMGCSqGSIb3DQEHAaCCAQQEggEAVVSpOKf9zJYc" +
    		"tyvqgeHfO9JkobPYihUZcW9TbYzAUiJGEsElNCnLUaO0+MZG0TS7hlzqKKvrdXc7" +
    		"O/8C7c8YyjYF5YrLiaYS8cw3VbaQ2M1NWsLGzxF1pxsR9sMDJvfrryPaWj4eTi3Y" +
    		"UqRNS+GTa4quX4xbmB0KqMpCtrvuk4S9cgaJGwxmSE7N3omzvERTUxp7nVSHtms5" +
    		"lVMb082JFlABT1/o2mL5O6qFG119JeuS1+ZiL1AEy//gRs556OE1TB9UEQU2bFUm" +
    		"zBD4VHvkOOB/7X944v9lmK5y9sFv+vnf/34catL1A+ZNLwtd1Qq2VirqJxRK/T61" +
    		"QoSWj4rGpw==";
    
    private static final String TEST_KEY_ALIAS = "p11testkey1234";
    
    private final String sharedLibrary;
    private final String slot;
    private final String pin;
    private final String existingKey1;
    
    private final File pdfSampleFile;
    private final File odfSampleFile;
    private final File ooxmlSampleFile;

    private final IWorkerSession workerSession = getWorkerSession();
    private final IGlobalConfigurationSession globalSession = getGlobalSession();
    
    public P11SignTest() {
        File home = new File(System.getenv("SIGNSERVER_HOME"));
        assertTrue("Environment variable SIGNSERVER_HOME", home.exists());
        pdfSampleFile = new File(home, "res/test/pdf/sample.pdf");
        odfSampleFile = new File(home, "res/signingtest/input/test.odt");
        ooxmlSampleFile = new File(home, "res/signingtest/input/test.docx");
        sharedLibrary = getConfig().getProperty("test.p11.sharedlibrary");
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
    
    private void setPDFSignerProperties(final int workerId, final boolean cache) throws Exception {
        // Setup worker
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".CLASSPATH", "org.signserver.module.pdfsigner.PDFSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "PDFSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARY", sharedLibrary);
        workerSession.setWorkerProperty(workerId, "SLOT", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
    }
    
    /** Tests that the getCertificateRequest method generates a request. */
    public void testGenerateCSR() throws Exception {
        try {
            setPDFSignerProperties(WORKER_PDF, false);
            workerSession.reloadConfiguration(WORKER_PDF);
            
            // Tests generating a CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
            Base64SignerCertReqData csr = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(WORKER_PDF, certReqInfo, false);
            assertNotNull(csr);
            assertNotNull(csr.getBase64CertReq());
            assertTrue(csr.getBase64CertReq().length > 0);
            
            // Test for an non-existing key label
            setPDFSignerProperties(WORKER_PDF, false);
            workerSession.setWorkerProperty(WORKER_PDF, "DEFAULTKEY", "NON-EXISTING-KEY-LABEL");
            workerSession.reloadConfiguration(WORKER_PDF);
            try {
                certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
                getWorkerSession().getCertificateRequest(WORKER_PDF, certReqInfo, false);
                fail("Should have thrown exception as the DEFAULTKEY does not exist");
            } catch (CryptoTokenOfflineException ok) { // NOPMD
                // OK
            }
        } finally {
            removeWorker(WORKER_PDF);
        }
    }

    /**
     * Tests setting up a PDF Signer, giving it a certificate and sign a document.
     */
    public void testPDFSigner_uncached() throws Exception {
        try {
            setPDFSignerProperties(WORKER_PDF, false);
            workerSession.reloadConfiguration(WORKER_PDF);
            
            pdfSignerTest();
        } finally {
            removeWorker(WORKER_PDF);
        }
    }
    
    /**
     * Tests setting up a PDF Signer, giving it a certificate and sign a document.
     */
    public void testPDFSigner_cached() throws Exception {
        try {
            setPDFSignerProperties(WORKER_PDF, true);
            workerSession.reloadConfiguration(WORKER_PDF);
            
            pdfSignerTest();
        } finally {
            removeWorker(WORKER_PDF);
        }
    }
    
    private void pdfSignerTest() throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(WORKER_PDF, certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(WORKER_PDF, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(WORKER_PDF, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(WORKER_PDF);

        // Test active
        List<String> errors = workerSession.getStatus(WORKER_PDF).getFatalErrors();
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
    
    private void setTimeStampSignerProperties(final int workerId, final boolean cache) throws IOException {
        // Setup worker
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".CLASSPATH", "org.signserver.module.tsa.TimeStampSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "TSSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARY", sharedLibrary);
        workerSession.setWorkerProperty(workerId, "SLOT", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "DEFAULTTSAPOLICYOID", "1.2.3");
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
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
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(WORKER_TSA, certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).addExtension(org.bouncycastle.asn1.x509.X509Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(WORKER_TSA, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(WORKER_TSA, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(WORKER_TSA);

        // Test active
        List<String> errors = workerSession.getStatus(WORKER_TSA).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
        byte[] requestBytes = timeStampRequest.getEncoded();
        GenericSignRequest signRequest = new GenericSignRequest(567, requestBytes);
        final GenericSignResponse res = (GenericSignResponse) workerSession.process(WORKER_TSA, signRequest, new RequestContext());
        Certificate signercert = res.getSignerCertificate();
        assertNotNull(signercert);
        final TimeStampResponse timeStampResponse = new TimeStampResponse((byte[]) res.getProcessedData());
        timeStampResponse.validate(timeStampRequest);

        assertEquals("Token granted", PKIStatus.GRANTED, timeStampResponse.getStatus());
        assertNotNull("Got timestamp token", timeStampResponse.getTimeStampToken());
    }
    
    private void setMRTDSODSignerProperties(final int workerId, final boolean cache) throws IOException {
        // Setup worker
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".CLASSPATH", "org.signserver.module.mrtdsodsigner.MRTDSODSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "SODSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARY", sharedLibrary);
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
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(workerId, certReqInfo, false);

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
        List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        HashMap<Integer, byte[]> dgs = new HashMap<Integer, byte[]>();
        dgs.put(1, "Yy==".getBytes());
        dgs.put(2, "Yy==".getBytes());
        dgs.put(3, "Yy==".getBytes());
        final SODSignRequest signRequest = new SODSignRequest(233, dgs);
        final SODSignResponse res = (SODSignResponse) workerSession.process(workerId, signRequest, new RequestContext());
        Certificate signercert = res.getSignerCertificate();
        assertNotNull(signercert);
    }
    
    private void setCMSSignerProperties(final int workerId, final boolean cached) throws IOException {
        // Setup worker
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".CLASSPATH", "org.signserver.module.cmssigner.CMSSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "CMSSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARY", sharedLibrary);
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
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(workerId, certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(workerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(workerId, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(workerId);

        // Test active
        List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        signGenericDocument(workerId, "Sample data".getBytes());
    }
    
    private void setXMLSignerProperties(final int workerId, final boolean cache) throws IOException {
        // Setup worker
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".CLASSPATH", "org.signserver.module.xmlsigner.XMLSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "XMLSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARY", sharedLibrary);
        workerSession.setWorkerProperty(workerId, "SLOT", slot);
        workerSession.setWorkerProperty(workerId, "PIN", pin);
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", existingKey1);
        workerSession.setWorkerProperty(workerId, "CACHE_PRIVATEKEY", String.valueOf(cache));
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
    
    private void xmlSigner(final int workerId) throws Exception {
        // Generate CSR
        PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + workerId, null);
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(workerId, certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(workerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(workerId, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(workerId);

        // Test active
        List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
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
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".CLASSPATH", "org.signserver.module.odfsigner.ODFSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "ODFSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARY", sharedLibrary);
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
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(workerId, certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(workerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(workerId, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(workerId);

        // Test active
        List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        signGenericDocument(workerId, readFile(odfSampleFile));
    }
    
    private void setOOXMLSignerProperties(final int workerId, final boolean cache) throws IOException {
        // Setup worker
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".CLASSPATH", "org.signserver.module.ooxmlsigner.OOXMLSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "OOXMLSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARY", sharedLibrary);
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
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(workerId, certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(workerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(workerId, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(workerId);

        // Test active
        List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        signGenericDocument(workerId, readFile(ooxmlSampleFile));
    }

    private void setMSAuthTimeStampSignerProperties(final int workerId, final boolean cache) throws IOException {
        // Setup worker
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".CLASSPATH", "org.signserver.module.tsa.MSAuthCodeTimeStampSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "MSAuthTSSignerP11");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "SHAREDLIBRARY", sharedLibrary);
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
        Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(workerId, certReqInfo, false);

        // Issue certificate
        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
        KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
        X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=TestP11 Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).addExtension(org.bouncycastle.asn1.x509.X509Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

        // Install certificate and chain
        workerSession.uploadSignerCertificate(workerId, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.uploadSignerCertificateChain(workerId, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
        workerSession.reloadConfiguration(workerId);

        // Test active
        List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
        assertEquals("errors: " + errors, 0, errors.size());

        // Test signing
        GenericSignRequest signRequest = new GenericSignRequest(678, MSAUTHCODE_REQUEST_DATA.getBytes());
        final GenericSignResponse res = (GenericSignResponse) workerSession.process(workerId, signRequest, new RequestContext());
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
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".CLASSPATH", "org.signserver.module.cmssigner.CMSSigner");
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", PKCS11CryptoToken.class.getName());
            globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "DEFAULT.SHAREDLIBRARY", sharedLibrary);
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
            globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "DEFAULT.SLOT");
        }
    }
    
    private Set<String> getKeyAliases(final int workerId) throws Exception {
        Collection<KeyTestResult> testResults = workerSession.testKey(workerId, "all", pin.toCharArray());
        final HashSet<String> results = new HashSet<String>();
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
                workerSession.removeKey(workerId, TEST_KEY_ALIAS);
                aliases1 = getKeyAliases(workerId);
            }
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " already exists and removing it failed");
            }

            // Generate a testkey
            workerSession.generateSignerKey(workerId, "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
            
            // Now expect the new TEST_KEY_ALIAS
            Set<String> expected = new HashSet<String>(aliases1);
            expected.add(TEST_KEY_ALIAS);
            Set<String> aliases2 = getKeyAliases(workerId);
            assertEquals("new key added", expected, aliases2);
            
        } finally {
            try {
                workerSession.removeKey(workerId, TEST_KEY_ALIAS);
            } catch (SignServerException ignored) {}
            removeWorker(workerId);
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
                workerSession.generateSignerKey(workerId, "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
                aliases1 = getKeyAliases(workerId);
            }
            if (!aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " did not exist and it could not be created");
            }
            
            // Remove the key
            workerSession.removeKey(workerId, TEST_KEY_ALIAS);
            
            // Now expect the TEST_KEY_ALIAS to have been removed
            Set<String> aliases2 = getKeyAliases(workerId);
            Set<String> expected = new HashSet<String>(aliases1);
            expected.remove(TEST_KEY_ALIAS);
            assertEquals("new key removed", expected, aliases2);
        } finally {
            removeWorker(workerId);
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
            setXMLSignerProperties(workerId, false);
            workerSession.removeWorkerProperty(workerId, "SHAREDLIBRARY");
            workerSession.reloadConfiguration(workerId);
            
            final List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
            assertTrue("Should contain error",
                    errors.contains("Failed to initialize crypto token: Missing SHAREDLIBRARY property"));
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
            setXMLSignerProperties(workerId, false);
            workerSession.setWorkerProperty(workerId, "SHAREDLIBRARY", "/foo/bar/libdummy.so");
            workerSession.reloadConfiguration(workerId);
            
            final List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
            assertTrue("Should contain error",
                    errors.contains("Failed to initialize crypto token: Not possible to create provider. See cause.: The file /foo/bar/libdummy.so can't be read."));
        } finally {
            removeWorker(workerId);
        }
    }
}