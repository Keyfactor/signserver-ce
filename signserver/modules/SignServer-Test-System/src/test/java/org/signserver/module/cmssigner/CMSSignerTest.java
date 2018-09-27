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
package org.signserver.module.cmssigner;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static junit.framework.TestCase.fail;
import org.apache.commons.io.FileUtils;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.encoders.Base64;
import org.junit.After;
import org.junit.Assume;
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
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.test.utils.builders.CryptoUtils;

/**
 * Tests for CMSSigner.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CMSSignerTest  {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CMSSignerTest.class);
    
    private static final int WORKERID_ECDSA = 8000;
    private static final int WORKERID_DSA = 8001;
    
    private static final double TEST_NOT_SUPPORTS_THIS_AND_OLDER_VERSIONS= 1.7;
    private static final double JAVA_VERSION;
    
    private final WorkerSession workerSession;
    private final ProcessSessionRemote processSession;
    private final ModulesTestCase mt = new ModulesTestCase();
    
    private static final String TEST_KEY_ALIAS = "testkey123";
    
    static {
        JAVA_VERSION = ModulesTestCase.getJavaVersion();
    }

    public CMSSignerTest() {
        workerSession = mt.getWorkerSession();
        processSession = mt.getProcessSession();
    }
     
    
    @Before    
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @After    
    public void tearDown() throws Exception {
        TestingSecurityManager.remove();
    }	

    @Test
    public void test00SetupDatabase() throws Exception {
        mt.addSigner("org.signserver.module.cmssigner.CMSSigner", true);
    }

    /**
     * Tests that the signer can produce a CMS structure and that it returns
     * the signer's certficate and that it is included in the structure and
     * that it can be used to verify the signature and that the signed content
     * also is included. Also test that the default signature algorithm is SHA256withRSA
     * @throws Exception In case of error.
     */
    @Test
    public void test01BasicCMSSignRSA() throws Exception {
        LOG.debug(">test01BasicCMSSignRSA");

        helperBasicCMSSign(mt.getSignerIdDummy1(), null, "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11", null, 1);
        
        LOG.debug("<test01BasicCMSSignRSA");
    }
    
    /**
     * Test setting SIGNATUREALGORITHM to a non-default value.
     * @throws Exception
     */
    @Test
    public void test02BasicCMSSignSHA256withRSA() throws Exception {
        helperBasicCMSSign(mt.getSignerIdDummy1(), "SHA256withRSA", "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11",
                null, 1);
    }
    
    /**
     * Test that signing fails when using wrong certificate and VERIFY_SIGNATURE
     * is TRUE (default) but it works when set as FALSE.
     *
     * @throws Exception
     */
    @Test
    public void test10SignatureValidationWrongCertificate() throws Exception {
        LOG.info("test10SignatureValidationWrongCertificate");       
        
        final int reqid = 37;

        final String testDocument = "Something to sign...123";

        final GenericSignRequest signRequest =
                new GenericSignRequest(reqid, testDocument.getBytes());
        
        File keystore = new File(mt.getSignServerHome(), "res/test/dss10/dss10_keystore.p12");
        File keystoreFile = File.createTempFile("dss10_keystore_temp", ".p12");
        FileUtils.copyFile(keystore, keystoreFile);

        try {
            workerSession.setWorkerProperty(mt.getSignerIdDummy1(), "KEYSTOREPATH", keystoreFile.getAbsolutePath());
            workerSession.reloadConfiguration(mt.getSignerIdDummy1());
            workerSession.generateSignerKey(new WorkerIdentifier(mt.getSignerIdDummy1()), "RSA", "1024", TEST_KEY_ALIAS, null);

            // Generate CSR
            final ISignerCertReqInfo req
                    = new PKCS10CertReqInfo("SHA1WithRSA", "CN=Worker" + mt.getSignerIdDummy1(), null);
            Base64SignerCertReqData reqData
                    = (Base64SignerCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(mt.getSignerIdDummy1()), req, false, TEST_KEY_ALIAS);

            // Issue certificate
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Base64.decode(reqData.getBase64CertReq()));
            KeyPair issuerKeyPair = CryptoUtils.generateRSA(512);
            X509CertificateHolder cert = new X509v3CertificateBuilder(new X500Name("CN=Test Issuer"), BigInteger.ONE, new Date(), new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)), csr.getSubject(), csr.getSubjectPublicKeyInfo()).build(new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKeyPair.getPrivate()));

            // Install certificate and chain
            workerSession.uploadSignerCertificate(mt.getSignerIdDummy1(), cert.getEncoded(), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(mt.getSignerIdDummy1(), Arrays.asList(cert.getEncoded()), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(mt.getSignerIdDummy1());

            // Test the status of the worker
            WorkerStatus actualStatus = workerSession.getStatus(new WorkerIdentifier(mt.getSignerIdDummy1()));            
            assertEquals("should be error as the right signer certificate is not configured", 1, actualStatus.getFatalErrors().size());
            assertTrue("error should talk about incorrect signer certificate: " + actualStatus.getFatalErrors().toString(), actualStatus.getFatalErrors().get(0).contains("Certificate does not match key"));

            try {
                processSession.process(new WorkerIdentifier(mt.getSignerIdDummy1()), signRequest, new RemoteRequestContext());                
                fail("Should fail complaining about signature validation failure");
            } catch (SignServerException e) {
                // expected
            } catch (Exception e) {
                fail("Unexpected exception thrown: " + e.getClass().getName());
            }

            // Now change to - not verifying signature and signing should work
            workerSession.setWorkerProperty(mt.getSignerIdDummy1(), "VERIFY_SIGNATURE", "FALSE");
            workerSession.reloadConfiguration(mt.getSignerIdDummy1());
            try {
                processSession.process(new WorkerIdentifier(mt.getSignerIdDummy1()), signRequest, new RemoteRequestContext());
            } catch (SignServerException e) {
                fail("SignServerException should not be thrown");
            }

        } finally {
            workerSession.removeKey(new WorkerIdentifier(mt.getSignerIdDummy1()), TEST_KEY_ALIAS);
            workerSession.removeWorkerProperty(mt.getSignerIdDummy1(), "SIGNERCERT");
            workerSession.removeWorkerProperty(mt.getSignerIdDummy1(), "SIGNERCERTCHAIN ");
            workerSession.reloadConfiguration(mt.getSignerIdDummy1());
            FileUtils.deleteQuietly(keystoreFile);
        }
    }
    
    /**
     * Test with ECDSA encryption algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void test03BasicCMSSignSHA1withECDSA() throws Exception {
        // Setup signer
        final File keystore = new File(mt.getSignServerHome(), "res/test/dss10/dss10_signer5ec.p12");
        if (!keystore.exists()) {
            throw new FileNotFoundException(keystore.getAbsolutePath());
        }
        mt.addP12DummySigner("org.signserver.module.cmssigner.CMSSigner", WORKERID_ECDSA,
            "TestCMSSignerP12ECDSA", keystore, "foo123", "signerec");
        workerSession.reloadConfiguration(WORKERID_ECDSA);
        
        helperBasicCMSSign(WORKERID_ECDSA, "SHA1withECDSA", "1.3.14.3.2.26", "1.2.840.10045.4.1", null, 1);
        
        mt.removeWorker(WORKERID_ECDSA);
    }

    /**
     * Test with DSA encryption algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void test04BasicCMSSignSHA1withDSA() throws Exception {
        // Setup signer
        final File keystore = new File(mt.getSignServerHome(), "res/test/dss10/dss10_tssigner6dsa.jks");
        if (!keystore.exists()) {
            throw new FileNotFoundException(keystore.getAbsolutePath());
        }
        mt.addJKSDummySigner("org.signserver.module.cmssigner.CMSSigner", WORKERID_DSA, "TestCMSSignerJKSDSA", keystore, "foo123", "mykey");
        workerSession.reloadConfiguration(WORKERID_DSA);
        
        helperBasicCMSSign(WORKERID_DSA, "SHA1withDSA", "1.3.14.3.2.26", "1.2.840.10040.4.3", null, 1);
        
        mt.removeWorker(WORKERID_DSA);
    }
    
    /**
     * Test with SHA256withDSA encryption algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void test08BasicCMSSignSHA256withDSA() throws Exception {
        // Looks like SHA256withDSA is not supported as signature algorithm by SUN provider in all java 7 versions.Example: 1.7.0_45 & 1.7.0_55
        // so let's run this test with Java 8 and higher versions only
        Assume.assumeTrue("Test not supported by java version " + JAVA_VERSION, JAVA_VERSION > TEST_NOT_SUPPORTS_THIS_AND_OLDER_VERSIONS);

        // Setup signer
        final File keystore = new File(mt.getSignServerHome(), "res/test/dss10/dss10_tssigner6dsa.jks");
        if (!keystore.exists()) {
            throw new FileNotFoundException(keystore.getAbsolutePath());
        }
        mt.addJKSDummySigner("org.signserver.module.cmssigner.CMSSigner", WORKERID_DSA, "TestCMSSignerJKSDSA", keystore, "foo123", "mykey");
        workerSession.reloadConfiguration(WORKERID_DSA);

        helperBasicCMSSign(WORKERID_DSA, "SHA256withDSA", "2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.3.2", null, 1);

        mt.removeWorker(WORKERID_DSA);
    }
    
    /**
     * Test with SHA256withECDSA encryption algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void test09BasicCMSSignSHA256withECDSA() throws Exception {
        // Setup signer
        final File keystore = new File(mt.getSignServerHome(), "res/test/dss10/dss10_signer5ec.p12");
        if (!keystore.exists()) {
            throw new FileNotFoundException(keystore.getAbsolutePath());
        }
        mt.addP12DummySigner("org.signserver.module.cmssigner.CMSSigner", WORKERID_ECDSA,
            "TestCMSSignerP12ECDSA", keystore, "foo123", "signerec");
        workerSession.reloadConfiguration(WORKERID_ECDSA);
        
        helperBasicCMSSign(WORKERID_ECDSA, "SHA256withECDSA", "2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.2", null, 1);
        
        mt.removeWorker(WORKERID_ECDSA);
    }
    
    /**
     * Test with no included certificates.
     * 
     * @throws Exception
     */
    @Test
    public void test05IncludeNoCerts() throws Exception {
        helperBasicCMSSign(mt.getSignerIdDummy1(), null, "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11", "0", 0);
    }
    
    /**
     * Test explicitly specifying 1 certificate to be included.
     * 
     * @throws Exception
     */
    @Test
    public void test06ExplicitIncludedCerts() throws Exception {
        helperBasicCMSSign(mt.getSignerIdDummy1(), null, "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11", "1", 1);
    }
    
    /**
     * Test specifying more certificates than are available.
     * 
     * @throws Exception
     */
    @Test
    public void test07TruncatedIncludedCerts() throws Exception {
        helperBasicCMSSign(mt.getSignerIdDummy1(), null, "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11", "2", 1);
    }

    private void helperBasicCMSSign(final int workerId, final String sigAlg, final String expectedDigAlgOID,
            final String expectedEncAlgOID, final String includedCertificateLevelsProperty,
            final int expectedIncludedCertificateLevels) throws Exception {
        final int reqid = 37;

        final String testDocument = "Something to sign...123";

        final GenericSignRequest signRequest =
                new GenericSignRequest(reqid, testDocument.getBytes());

        // override signature algorithm if set
        if (sigAlg != null) {
            workerSession.setWorkerProperty(workerId, CMSSigner.SIGNATUREALGORITHM_PROPERTY, sigAlg);
        } else {
            workerSession.removeWorkerProperty(workerId, CMSSigner.SIGNATUREALGORITHM_PROPERTY);
        }
        
        if (includedCertificateLevelsProperty != null) {
            workerSession.setWorkerProperty(workerId,
                    WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS,
                    includedCertificateLevelsProperty);
        } else {
            workerSession.removeWorkerProperty(workerId, WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS);
        }
        
        workerSession.reloadConfiguration(workerId);
        
        final GenericSignResponse res =
                (GenericSignResponse) processSession.process(new WorkerIdentifier(workerId), signRequest, new RemoteRequestContext());
        final byte[] data = res.getProcessedData();
   
        // Answer to right question
        ModulesTestCase.assertSame("Request ID", reqid, res.getRequestID());

        try ( // Output for manual inspection
                FileOutputStream fos = new FileOutputStream(
                        new File(mt.getSignServerHome(),
                                "tmp" + File.separator + "signedcms_" + sigAlg + ".p7s"))) {
            fos.write((byte[]) data);
        }

        // Check certificate returned
        final Certificate signercert = res.getSignerCertificate();
        ModulesTestCase.assertNotNull("Signer certificate", signercert);

        // Check that the signed data contains the document (i.e. not detached)
        final CMSSignedData signedData = new CMSSignedData(data);
        final byte[] content = (byte[]) signedData.getSignedContent()
                .getContent();
        ModulesTestCase.assertEquals("Signed document", testDocument, new String(content));

        // Get signers
        final Collection signers = signedData.getSignerInfos().getSigners();
        final SignerInformation signer
                = (SignerInformation) signers.iterator().next();

        final SignerInformationVerifier sigVerifier =
                new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder().build()).setProvider("BC").build(signercert.getPublicKey());

        // Verify using the signer's certificate
        ModulesTestCase.assertTrue("Verification using signer certificate",
                signer.verify(sigVerifier));

        // Check that the signer's certificate is included
        final Store certStore = signedData.getCertificates();
       
        final SignerId sid = signer.getSID();
        final Selector certSelector =
                new AttributeCertificateHolder(sid.getIssuer(),
                                               sid.getSerialNumber());
                
        Collection<? extends X509CertificateHolder> signerCerts =
                certStore.getMatches(certSelector);
        
        ModulesTestCase.assertEquals("Certificate included", expectedIncludedCertificateLevels, signerCerts.size());
        if (!signerCerts.isEmpty()) {
            final X509CertificateHolder certHolder =
                    signerCerts.iterator().next();
            final X509CertificateObject cert =
                    new X509CertificateObject(certHolder.toASN1Structure());
            ModulesTestCase.assertEquals(signercert, cert);
        }

        // check the signature algorithm
        ModulesTestCase.assertEquals("Digest algorithm", expectedDigAlgOID, signer.getDigestAlgorithmID().getAlgorithm().getId());
        ModulesTestCase.assertEquals("Encryption algorithm", expectedEncAlgOID, signer.getEncryptionAlgOID());   
    }

    /**
     * Remove the workers created etc.
     * @throws Exception in case of error
     */
    @Test
    public void test99TearDownDatabase() throws Exception {
        mt.removeWorker(mt.getSignerIdDummy1());
    }
}
