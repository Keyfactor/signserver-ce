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
package org.signserver.module.xades.signer;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.ejb.EJBException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static junit.framework.TestCase.fail;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.testutils.ModulesTestCase;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import xades4j.providers.CertificateValidationProvider;
import xades4j.providers.impl.DefaultTimeStampVerificationProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;
import xades4j.verification.SignatureSpecificVerificationOptions;
import xades4j.verification.XAdESVerificationResult;
import xades4j.verification.XadesVerificationProfile;
import xades4j.verification.XadesVerifier;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.test.utils.builders.CryptoUtils;

/**
 * System tests for the XAdESSigner.
 *
 * Note: Unit tests should be placed in the SignServer-Module-XAdES project.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class XAdESSignerTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(XAdESSignerTest.class);

    private static final int WORKER_ID = 9901;
    private static final String WORKER_NAME = "TestXAdESSigner";
    private static final int TS_ID = 9902;
    private static final String TS_NAME = "TestTimeStampSigner";

    private final WorkerSession workerSession = getWorkerSession();
    private final ProcessSessionRemote processSession = getProcessSession();
    
    private static final String TEST_KEY_ALIAS = "testkey123";
    
    @Before
    @Override
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    private void internalSigningAndVerify(String tsaDigestAlgorithm, String acceptedTSADigestAlgorithm) throws Exception {        
        try {

            addTimeStampSigner(TS_ID, TS_NAME, true);
            addSigner(XAdESSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            
            workerSession.setWorkerProperty(TS_ID, "DEFAULTTSAPOLICYOID", "1.2.3");
            workerSession.setWorkerProperty(TS_ID, "ACCEPTEDALGORITHMS", acceptedTSADigestAlgorithm);
            
            workerSession.setWorkerProperty(WORKER_ID, "XADESFORM", "T");
            workerSession.setWorkerProperty(WORKER_ID, "TSA_WORKER", TS_NAME);            
            if (tsaDigestAlgorithm != null) {
                workerSession.setWorkerProperty(WORKER_ID, "TSA_DIGESTALGORITHM", tsaDigestAlgorithm);
            }
            
            workerSession.reloadConfiguration(TS_ID);
            workerSession.reloadConfiguration(WORKER_ID);

            GenericSignRequest request = new GenericSignRequest(100, "<test100/>".getBytes(StandardCharsets.UTF_8));
            GenericSignResponse response = (GenericSignResponse) processSession.process(new WorkerIdentifier(WORKER_ID), request, new RemoteRequestContext());

            byte[] data = response.getProcessedData();
            final String signedXml = new String(data);
            LOG.debug("signedXml: " + signedXml);

            // Validation: setup
            CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(workerSession.getSignerCertificateChain(new WorkerIdentifier(WORKER_ID))));
            KeyStore trustAnchors = KeyStore.getInstance("JKS");
            trustAnchors.load(null, "foo123".toCharArray());
            final List<Certificate> signerCertificateChain =
                workerSession.getSignerCertificateChain(new WorkerIdentifier(WORKER_ID));
            final List<Certificate> tsSignerCertificateChain =
                workerSession.getSignerCertificateChain(new WorkerIdentifier(TS_ID));
            trustAnchors.setCertificateEntry("signerIssuer", signerCertificateChain.get(signerCertificateChain.size() - 1));
            trustAnchors.setCertificateEntry("tsIssuer", tsSignerCertificateChain.get(tsSignerCertificateChain.size() - 1));

            CertificateValidationProvider certValidator = new PKIXCertificateValidationProvider(trustAnchors, false, certStore);

            XadesVerificationProfile p =
                    new XadesVerificationProfile(certValidator).withTimeStampTokenVerifier(DefaultTimeStampVerificationProvider.class);
            XadesVerifier verifier = p.newVerifier();

            // Validation: parse
            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            final DocumentBuilder builder = factory.newDocumentBuilder();
            final Document doc = builder.parse(new ByteArrayInputStream(data));
            Element node = doc.getDocumentElement();

            XAdESVerificationResult r = verifier.verify(node, new SignatureSpecificVerificationOptions());

            LOG.debug("signature form: " + r.getSignatureForm().name());
            assertEquals("T", r.getSignatureForm().name());
            assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", r.getSignatureAlgorithmUri());
        } finally {
            removeWorker(WORKER_ID);
            removeWorker(TS_ID);
        }
    }
    
    /**
     * Tests XADES-T signing with default TSA_DIGEST_ALGORITHM algorithm.
     *
     * @throws Exception
     */
    @Test
    public void testBasicSigningXAdESFormT_TSA_DIGEST_ALGO_Default_SHA256() throws Exception {
        LOG.info("testBasicSigningXAdESFormT_TSA_DIGEST_ALGO_Default_SHA256");
        internalSigningAndVerify(null, "SHA256");
    }
    
    /**
     * Tests XADES-T signing with SHA-1 TSA_DIGEST_ALGORITHM algorithm.
     *
     * @throws Exception
     */
    @Test
    public void testBasicSigningXAdESFormT_TSA_DIGEST_ALGO_SHA1() throws Exception {
        LOG.info("testBasicSigningXAdESFormT_TSA_DIGEST_ALGO_SHA1");
        internalSigningAndVerify("SHA1", "SHA1");
    }
    
    /**
     * Tests XADES-T signing with SHA-512 TSA_DIGEST_ALGORITHM algorithm.
     *
     * @throws Exception
     */
    @Test
    public void testBasicSigningXAdESFormT_TSA_DIGEST_ALGO_SHA512() throws Exception {
        LOG.info("testBasicSigningXAdESFormT_TSA_DIGEST_ALGO_SHA512");
        internalSigningAndVerify("SHA512", "SHA512");
    }
    
    /**
     * Test that signing fails when using wrong certificate and VERIFY_SIGNATURE
     * is TRUE (default) but it works when set as FALSE.
     *
     * @throws Exception
     */
    @Test
    public void testSignatureValidationWrongCertificate() throws Exception {
        LOG.info("testSignatureValidationWrongCertificate");
        GenericSignRequest signRequest = new GenericSignRequest(100, "<test100/>".getBytes(StandardCharsets.UTF_8));

        File keystore = new File(getSignServerHome(), "res/test/dss10/dss10_keystore.p12");
        File keystoreFile = File.createTempFile("dss10_keystore_temp", ".p12");
        FileUtils.copyFile(keystore, keystoreFile);

        try {
            addSigner(XAdESSigner.class.getName(), WORKER_ID, WORKER_NAME, true);
            workerSession.setWorkerProperty(WORKER_ID, "KEYSTOREPATH", keystoreFile.getAbsolutePath());
            workerSession.reloadConfiguration(WORKER_ID);
            workerSession.generateSignerKey(new WorkerIdentifier(WORKER_ID), "RSA", "1024", TEST_KEY_ALIAS, null);

            // Generate CSR
            final ISignerCertReqInfo req
                    = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + WORKER_ID, null);
            Base64SignerCertReqData reqData
                    = (Base64SignerCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(WORKER_ID), req, false, TEST_KEY_ALIAS);

            // Issue certificate
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
            KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
            X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=Test Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

            // Install certificate and chain
            workerSession.uploadSignerCertificate(WORKER_ID, cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(WORKER_ID, Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(WORKER_ID);

            // Test the status of the worker
            WorkerStatus actualStatus = workerSession.getStatus(new WorkerIdentifier(WORKER_ID));
            assertEquals("should be error as the right signer certificate is not configured", 1, actualStatus.getFatalErrors().size());
            assertTrue("error should talk about incorrect signer certificate: " + actualStatus.getFatalErrors().toString(), actualStatus.getFatalErrors().get(0).contains("Certificate does not match key"));

            try {
                processSession.process(new WorkerIdentifier(WORKER_ID), signRequest, new RemoteRequestContext());
                fail("Should fail complaining about signature validation failure");
            } catch (SignServerException e) {
                // expected
            } catch (Exception e) {
                fail("Unexpected exception thrown: " + e.getClass().getName());
            }

            // Now change to - not verifying signature and signing should work
            workerSession.setWorkerProperty(WORKER_ID, "VERIFY_SIGNATURE", "FALSE");
            workerSession.reloadConfiguration(WORKER_ID);

            try {
                processSession.process(new WorkerIdentifier(WORKER_ID), signRequest, new RemoteRequestContext());
            } catch (SignServerException e) {
                fail("SignServerException should not be thrown");
            }
        } finally {
            workerSession.removeKey(new WorkerIdentifier(WORKER_ID), TEST_KEY_ALIAS);
            workerSession.removeWorkerProperty(WORKER_ID, "SIGNERCERT");
            workerSession.removeWorkerProperty(WORKER_ID, "SIGNERCERTCHAIN ");
            workerSession.reloadConfiguration(WORKER_ID);
            removeWorker(WORKER_ID);
            FileUtils.deleteQuietly(keystoreFile);
        }
    }
    
    /**
     * Tests XADES-T signing with illegal TSA_DIGEST_ALGORITHM algorithm and
     * check if fails.
     *
     * @throws Exception
     */
    @Test
    public void testBasicSigningXAdESFormT_Illegal_TSA_DIGEST_ALGO() throws Exception {
        LOG.info("testBasicSigningXAdESFormT_Illegal_TSA_DIGEST_ALGO");
        try {
            internalSigningAndVerify("Illegal_TSA_Digest_Algo", "SHA512");
            fail("It should have been failed");
        } catch (EJBException ex) {
            if (ex.getMessage() != null) { // On glassfish server, ex.getMessage() is NULL
                assertTrue(ex.getMessage(), ex.getMessage().contains("Unsupported TSA digest algorithm"));
            }
        }
    }

}
