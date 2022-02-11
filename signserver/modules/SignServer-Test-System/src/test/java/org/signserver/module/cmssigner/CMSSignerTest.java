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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.testutils.ModulesTestCase;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

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

    private final WorkerSession workerSession;
    private final ProcessSessionRemote processSession;
    private final ModulesTestCase mt = new ModulesTestCase();

    public CMSSignerTest() {
        workerSession = mt.getWorkerSession();
        processSession = mt.getProcessSession();
    }


    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @After
    public void tearDown() {
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
     */
    @Test
    public void test02BasicCMSSignSHA256withRSA() throws Exception {
        helperBasicCMSSign(mt.getSignerIdDummy1(), "SHA256withRSA", "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11",
                null, 1);
    }

    /**
     * Test with ECDSA encryption algorithm.
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
     */
    @Test
    public void test08BasicCMSSignSHA256withDSA() throws Exception {
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
     */
    @Test
    public void test05IncludeNoCerts() throws Exception {
        helperBasicCMSSign(mt.getSignerIdDummy1(), null, "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11", "0", 0);
    }

    /**
     * Test explicitly specifying 1 certificate to be included.
     */
    @Test
    public void test06ExplicitIncludedCerts() throws Exception {
        helperBasicCMSSign(mt.getSignerIdDummy1(), null, "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11", "1", 1);
    }

    /**
     * Test specifying more certificates than are available.
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
        assertSame("Request ID", reqid, res.getRequestID());

        try ( // Output for manual inspection
                FileOutputStream fos = new FileOutputStream(
                        new File(mt.getSignServerHome(),
                                "tmp" + File.separator + "signedcms_" + sigAlg + ".p7s"))) {
            fos.write(data);
        }

        // Check certificate returned
        final Certificate signercert = res.getSignerCertificate();
        assertNotNull("Signer certificate", signercert);

        // Check that the signed data contains the document (i.e. not detached)
        final CMSSignedData signedData = new CMSSignedData(data);
        final byte[] content = (byte[]) signedData.getSignedContent()
                .getContent();
        assertEquals("Signed document", testDocument, new String(content));

        // Get signers
        final Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        final SignerInformation signer = signers.iterator().next();

        final SignerInformationVerifier sigVerifier =
                new JcaSignerInfoVerifierBuilder(new JcaDigestCalculatorProviderBuilder().build()).setProvider("BC").build(signercert.getPublicKey());

        // Verify using the signer's certificate
        assertTrue("Verification using signer certificate", signer.verify(sigVerifier));

        // Check that the signer's certificate is included
        final Store<X509CertificateHolder> certStore = signedData.getCertificates();

        final SignerId sid = signer.getSID();
        final Selector certSelector =
                new AttributeCertificateHolder(sid.getIssuer(),
                                               sid.getSerialNumber());

        Collection<? extends X509CertificateHolder> signerCerts = certStore.getMatches(certSelector);
        assertEquals("Certificate included", expectedIncludedCertificateLevels, signerCerts.size());
        if (!signerCerts.isEmpty()) {
            final X509CertificateHolder certHolder = signerCerts.iterator().next();
            final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
            assertEquals(signercert, cert);
        }

        // check the signature algorithm
        assertEquals("Digest algorithm", expectedDigAlgOID, signer.getDigestAlgorithmID().getAlgorithm().getId());
        assertEquals("Encryption algorithm", expectedEncAlgOID, signer.getEncryptionAlgOID());
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
