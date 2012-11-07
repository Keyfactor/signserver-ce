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
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.test.utils.builders.CryptoUtils;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests for the PKCS11CryptoToken.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PKCS11CryptoTokenTest extends ModulesTestCase {
    
    private static final int WORKER_PDF = 20000;
    private static final int WORKER_TSA = 20001;
    
    private final String sharedLibrary;
    private final String slot;
    private final String pin;
    private final String existingKey1;
    
    private final File pdfSampleFile;

    public PKCS11CryptoTokenTest() {
        File home = new File(System.getenv("SIGNSERVER_HOME"));
        assertTrue("Environment variable SIGNSERVER_HOME", home.exists());
        pdfSampleFile = new File(home, "res/test/pdf/sample.pdf");
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
    
    private void setPDFSignerProperties() throws Exception {
        // Setup worker
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + WORKER_PDF + ".CLASSPATH", "org.signserver.module.pdfsigner.PDFSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + WORKER_PDF + ".SIGNERTOKEN.CLASSPATH", PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(WORKER_PDF, "NAME", "PDFSignerP11");
        workerSession.setWorkerProperty(WORKER_PDF, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(WORKER_PDF, "SHAREDLIBRARY", sharedLibrary);
        workerSession.setWorkerProperty(WORKER_PDF, "SLOT", slot);
        workerSession.setWorkerProperty(WORKER_PDF, "PIN", pin);
        workerSession.setWorkerProperty(WORKER_PDF, "DEFAULTKEY", existingKey1);
    }
    
    /** Tests that the getCertificateRequest method generates a request. */
    public void testGenerateCSR() throws Exception {
        try {
            setPDFSignerProperties();
            workerSession.reloadConfiguration(WORKER_PDF);
            
            // Tests generating a CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
            Base64SignerCertReqData csr = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(WORKER_PDF, certReqInfo, false);
            assertNotNull(csr);
            assertNotNull(csr.getBase64CertReq());
            assertTrue(csr.getBase64CertReq().length > 0);
            
            // Test for an non-existing key label
            setPDFSignerProperties();
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
    public void testPDFSigner() throws Exception {
        try {
            setPDFSignerProperties();
            workerSession.reloadConfiguration(WORKER_PDF);
            
            // Generate CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_PDF, null);
            Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(WORKER_PDF, certReqInfo, false);
            
            // Issue certificate
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
            KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
            X509CertificateHolder cert = new X509v3CertificateBuilder(csr.getSubject(), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), new X500Name("CN=TestP11 Issuer"), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));
            
            // Install certificate and chain
            workerSession.uploadSignerCertificate(WORKER_PDF, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER_PDF, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER_PDF);
            
            // Test active
            List<String> errors = workerSession.getStatus(WORKER_PDF).getFatalErrors();
            assertEquals("errors: " + errors, 0, errors.size());
            
            // Test signing
            signGenericDocument(WORKER_PDF, readFile(pdfSampleFile));
        } finally {
            removeWorker(WORKER_PDF);
        }
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
    
    private void setTimeStampSignerProperties(final int workerId) throws IOException {
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
    }
    
    /**
     * Tests setting up a TimeStamp Signer, giving it a certificate and request a time-stamp token.
     */
    public void testTSSigner() throws Exception {
        try {
            setTimeStampSignerProperties(WORKER_TSA);
            workerSession.reloadConfiguration(WORKER_TSA);
            
            // Generate CSR
            PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_TSA, null);
            Base64SignerCertReqData reqData = (Base64SignerCertReqData) getWorkerSession().getCertificateRequest(WORKER_TSA, certReqInfo, false);
            
            // Issue certificate
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
            KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
            X509CertificateHolder cert = new X509v3CertificateBuilder(csr.getSubject(), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), new X500Name("CN=TestP11 Issuer"), csr.getSubjectPublicKeyInfo()).addExtension(org.bouncycastle.asn1.x509.X509Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));
            
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
        } finally {
            removeWorker(WORKER_TSA);
        }
    }
}
