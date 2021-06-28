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
package org.signserver.validationservice.server;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.ValidationServiceConstants;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for the CRL Validator.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CRLValidatorTest extends ModulesTestCase {

    private static WorkerSessionRemote sSSession;
    private final ProcessSessionRemote processSession = getProcessSession();

    private File signServerHome;
    /** RootCA1 */
    private static X509Certificate certRootCA1;
    /** EndEntity1 signed by RootCA1 */
    private static X509Certificate certEndEntity1;
    /** EndEntity2 signed by RootCA1 */
    private static X509Certificate certEndEntity2;
    /** CRL for RootCA1 */
    private static X509CRL crlRootCA1;
    /** RootCA2 */
    private static X509Certificate certRootCA2;
    /** EndEntity3 signed by RootCA2 */
    private static X509Certificate certEndEntity3;
    /** EndEntity4 signed by RootCA2 */
    private static X509Certificate certEndEntity4;
    /** EndEntity5 signed by RootCA1, expired */
    private static X509Certificate certEndEntity5Expired;
    /** EndEntity6 signed by RootCA1, not yet valid */
    private static X509Certificate certEndEntity6NotYetValid;
    /** EndEntity7 signed by RootCA1, signed by wrong issuer */
    private static X509Certificate certEndEntity7WrongIssuer;
    /** EndEntity8 signed by RootCA1, with key usage electronic signature */
    private static X509Certificate certEndEntity8KeyUsageSig;
    /** CRL for RootCA2 */
    private static X509CRL crlRootCA2;

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        sSSession = ServiceLocator.getInstance().lookupRemote(WorkerSessionRemote.class);
        signServerHome = PathUtil.getAppHome();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        // Setup keys, certificates and CRLs: RootCA1
        File cdpFile1 = new File(signServerHome, "tmp" + File.separator + "rootca1.crl");
        URL cdpUrl1 = cdpFile1.toURI().toURL();
        CRLDistPoint crlDistPointCA1WithUrl = ValidationTestUtils.generateDistPointWithUrl(cdpUrl1);
        ArrayList<X509Certificate> chain1 = new ArrayList<>();

        KeyPair keysRootCA1 = KeyTools.genKeys("1024", "RSA");
        certRootCA1 = ValidationTestUtils.genCert("CN=RootCA1", "CN=RootCA1", keysRootCA1.getPrivate(), keysRootCA1.getPublic(),
                new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

        KeyPair keysEndEntity1 = KeyTools.genKeys("1024", "RSA");
        certEndEntity1 = ValidationTestUtils.genCert("CN=EndEntity1", "CN=RootCA1", keysRootCA1.getPrivate(), keysEndEntity1.getPublic(),
                new Date(0), new Date(System.currentTimeMillis() + 1000000), false, 0, crlDistPointCA1WithUrl);

        KeyPair keysEndEntity2 = KeyTools.genKeys("1024", "RSA");
        certEndEntity2 = ValidationTestUtils.genCert("CN=EndEntity2", "CN=RootCA1", keysRootCA1.getPrivate(), keysEndEntity2.getPublic(),
                new Date(0), new Date(System.currentTimeMillis() + 1000000), false, 0, crlDistPointCA1WithUrl);

        KeyPair keysEndEntity5 = KeyTools.genKeys("1024", "RSA");
        certEndEntity5Expired = ValidationTestUtils.genCert("CN=EndEntity5", "CN=RootCA1", keysRootCA1.getPrivate(), keysEndEntity5.getPublic(),
                new Date(0), new Date(System.currentTimeMillis() - 2000000), false, 0, crlDistPointCA1WithUrl);

        KeyPair keysEndEntity6 = KeyTools.genKeys("1024", "RSA");
        certEndEntity6NotYetValid = ValidationTestUtils.genCert("CN=EndEntity6", "CN=RootCA1", keysRootCA1.getPrivate(), keysEndEntity6.getPublic(),
                new Date(System.currentTimeMillis() + 1000000), new Date(System.currentTimeMillis() + 3000000), false, 0, crlDistPointCA1WithUrl);

        KeyPair keysEndEntity7 = KeyTools.genKeys("1024", "RSA");
        PrivateKey notKeyOfRootCA1 = keysEndEntity1.getPrivate();
        certEndEntity7WrongIssuer = ValidationTestUtils.genCert("CN=EndEntity7", "CN=RootCA1", notKeyOfRootCA1, keysEndEntity7.getPublic(),
                new Date(0), new Date(System.currentTimeMillis() + 1000000), false, 0, crlDistPointCA1WithUrl);

        KeyPair keysEndEntity8 = KeyTools.genKeys("1024", "RSA");
        certEndEntity8KeyUsageSig = ValidationTestUtils.genCert("CN=EndEntity8", "CN=RootCA1", keysRootCA1.getPrivate(), keysEndEntity8.getPublic(),
                new Date(0), new Date(System.currentTimeMillis() + 1000000), false, X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation, crlDistPointCA1WithUrl);

        ArrayList<RevokedCertInfo> revoked = new ArrayList<>();
        revoked.add(new RevokedCertInfo("fingerprint".getBytes(),
                certEndEntity2.getSerialNumber().toByteArray(),
                new Date().getTime(),
                RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED,
                new Date(System.currentTimeMillis() + 1000000).getTime()));

        crlRootCA1 =
                ValidationTestUtils.genCRL(certRootCA1, keysRootCA1.getPrivate(),
                                           crlDistPointCA1WithUrl.getDistributionPoints()[0],
                                           revoked, 24, 1);

        try ( // Write CRL to file
                OutputStream out = new FileOutputStream(cdpFile1)) {
            out.write(crlRootCA1.getEncoded());
        }
        assertTrue(cdpFile1.exists());
        assertTrue(cdpFile1.canRead());
        chain1.add(certRootCA1);

        // Setup keys, certificates and CRLs: RootCA2
        File cdpFile2 = new File(signServerHome, "tmp" + File.separator + "rootca2.crl");
        URL cdpUrl2 = cdpFile2.toURI().toURL();
        CRLDistPoint crlDistPointCA2WithIssuer = ValidationTestUtils.generateDistPointWithIssuer("CN=RootCA2");
        ArrayList<X509Certificate> chain2 = new ArrayList<>();

        KeyPair keysRootCA2 = KeyTools.genKeys("1024", "RSA");
        certRootCA2 = ValidationTestUtils.genCert("CN=RootCA2", "CN=RootCA2", keysRootCA2.getPrivate(), keysRootCA2.getPublic(),
                new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

        KeyPair keysEndEntity3 = KeyTools.genKeys("1024", "RSA");
        certEndEntity3 = ValidationTestUtils.genCert("CN=EndEntity3", "CN=RootCA2", keysRootCA2.getPrivate(), keysEndEntity3.getPublic(),
                new Date(0), new Date(System.currentTimeMillis() + 1000000), false, 0, crlDistPointCA2WithIssuer);

        KeyPair keysEndEntity4 = KeyTools.genKeys("1024", "RSA");
        certEndEntity4 = ValidationTestUtils.genCert("CN=EndEntity4", "CN=RootCA2", keysRootCA2.getPrivate(), keysEndEntity4.getPublic(),
                new Date(0), new Date(System.currentTimeMillis() + 1000000), false, 0, crlDistPointCA2WithIssuer);

        ArrayList<RevokedCertInfo> revoked2 = new ArrayList<>();
        revoked2.add(new RevokedCertInfo("fingerprint2".getBytes(),
                certEndEntity4.getSerialNumber().toByteArray(),
                new Date().getTime(),
                RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED,
                new Date(System.currentTimeMillis() + 1000000).getTime()));

        crlRootCA2 = ValidationTestUtils.genCRL(certRootCA2, keysRootCA2.getPrivate(), crlDistPointCA2WithIssuer.getDistributionPoints()[0], revoked2, 24, 1);

        try ( // Write CRL to file
                OutputStream out2 = new FileOutputStream(cdpFile2)) {
            out2.write(crlRootCA2.getEncoded());
        }
        assertTrue(cdpFile2.exists());
        assertTrue(cdpFile2.canRead());
        chain2.add(certRootCA2);

        // Setup worker
        sSSession.setWorkerProperty(15, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        sSSession.setWorkerProperty(15, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.validationservice.server.ValidationServiceWorker");
        sSSession.setWorkerProperty(15, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.KeystoreCryptoToken");
        sSSession.setWorkerProperty(15, "KEYSTOREPATH",
                getSignServerHome() + File.separator + "res" + File.separator +
                "test" + File.separator + "dss10" + File.separator +
                "dss10_signer1.p12");
        sSSession.setWorkerProperty(15, "KEYSTORETYPE", "PKCS12");
        sSSession.setWorkerProperty(15, "KEYSTOREPASSWORD", "foo123");
        sSSession.setWorkerProperty(15, "DEFAULTKEY", "Signer 1");
        sSSession.setWorkerProperty(15, "AUTHTYPE", "NOAUTH");
        sSSession.setWorkerProperty(15, "VAL1.CLASSPATH", "org.signserver.validationservice.server.CRLValidator");
        sSSession.setWorkerProperty(15, "VAL1.ISSUER1.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(chain1));
        sSSession.setWorkerProperty(15, "VAL1.ISSUER2.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(chain2));
        sSSession.setWorkerProperty(15, "VAL1.ISSUER2.CRLPATHS", cdpUrl2.toExternalForm());
        sSSession.reloadConfiguration(15);
    }

    /**
     * Tests the certificate for EndEntity1 signed by RootCA1.
     * The certificate is valid.
     * It has a distribution point with an URL.
     */
    @Test
    public void test01NotRevoked() throws Exception {
        ValidateRequest req = new ValidateRequest(certEndEntity1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.VALID);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=RootCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=EndEntity1", CertTools.getSubjectDN(val.getCertificate()));
    }

    /**
     * Tests the certificate for EndEntity2 signed by RootCA1.
     * The certificate is revoked and included in the CRL.
     * It has a distribution point with an URL.
     */
    @Test
    public void test02Revoked() throws Exception {
        ValidateRequest req = new ValidateRequest(certEndEntity2, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);

        // Note: The best would be if we could get REVOKED as status from the CRLValidator and could then test with:
        //assertEquals(Validation.Status.REVOKED, val.getStatus());
        assertNotEquals(Validation.Status.VALID, val.getStatus());

        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=RootCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=EndEntity2", CertTools.getSubjectDN(val.getCertificate()));
    }

    /**
     * Tests the certificate for EndEntity3 signed by RootCA2.
     * The certificate is valid.
     * It has a distribution point with an issuer name.
     */
    @Test
    public void test03NotRevokedDPWithIssuer() throws Exception {
        ValidateRequest req = new ValidateRequest(certEndEntity3, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.VALID);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=RootCA2", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=EndEntity3", CertTools.getSubjectDN(val.getCertificate()));
    }

    /**
     * Tests the certificate for EndEntity4 signed by RootCA2.
     * The certificate is revoked and included in the CRL.
     * It has a distribution point with an issuer name.
     */
    @Test
    public void test04RevokedDPWithIssuer() throws Exception {
        ValidateRequest req = new ValidateRequest(certEndEntity4, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);

        // Note: The best would be if we could get REVOKED as status from the CRLValidator and could then test with:
        //assertEquals(Validation.Status.REVOKED, val.getStatus());
        assertNotEquals(Validation.Status.VALID, val.getStatus());

        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=RootCA2", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=EndEntity4", CertTools.getSubjectDN(val.getCertificate()));
    }

    /**
     * Tests the certificate for EndEntity5 signed by RootCA1.
     * The certificate is expired.
     */
    @Test
    public void test05Expired() throws Exception {
        ValidateRequest req = new ValidateRequest(certEndEntity5Expired, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertNotEquals("certificate should be expired", val.getStatus(), Validation.Status.VALID);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=RootCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=EndEntity5", CertTools.getSubjectDN(val.getCertificate()));
    }

    /**
     * Tests the certificate for EndEntity6 signed by RootCA1.
     * The certificate is not yet valid.
     */
    @Test
    public void test06NotYetValid() throws Exception {
        ValidateRequest req = new ValidateRequest(certEndEntity6NotYetValid, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertNotEquals("certificate should not be valid yet", val.getStatus(), Validation.Status.VALID);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=RootCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=EndEntity6", CertTools.getSubjectDN(val.getCertificate()));
    }

    /**
     * Tests the certificate for EndEntity7 signed by RootCA1.
     * The certificate is not valid as it is not signed width the right issuers key
     */
    @Test
    public void test07WrongIssuer() throws Exception {
        ValidateRequest req = new ValidateRequest(certEndEntity7WrongIssuer, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertNotEquals("certificate should not be valid", val.getStatus(), Validation.Status.VALID);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=RootCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=EndEntity7", CertTools.getSubjectDN(val.getCertificate()));
    }

    /**
     * Tests the certificate for EndEntity1 signed by RootCA1.
     * The certificate is not valid as it is not signed width the right issuers key
     */
    @Test
    public void test08KeyUsageSignature() throws Exception {
        // First: test one certificate that has CERTPURPOSE_ELECTRONIC_SIGNATURE and see that it works
        {
            ValidateRequest req = new ValidateRequest(certEndEntity8KeyUsageSig, ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
            ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

            Validation val = res.getValidation();
            assertNotNull(val);
            assertEquals("certificate should be valid for electronic signature", val.getStatus(), Validation.Status.VALID);
            assertNotNull(val.getStatusMessage());
            List<Certificate> cAChain = val.getCAChain();
            assertNotNull(cAChain);
            assertEquals("CN=RootCA1", CertTools.getSubjectDN(cAChain.get(0)));
            assertEquals("CN=EndEntity8", CertTools.getSubjectDN(val.getCertificate()));
        }

        // Second: test one certificate without CERTPURPOSE_ELECTRONIC_SIGNATURE and see that it fails
        {
            ValidateRequest req = new ValidateRequest(certEndEntity1, ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
            ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

            Validation val = res.getValidation();
            assertNotNull(val);
            assertNotEquals("certificate should fail is it does not have keyusage sig", val.getStatus(), Validation.Status.VALID);
            assertNotNull(val.getStatusMessage());
            List<Certificate> cAChain = val.getCAChain();
            assertNotNull(cAChain);
            assertEquals("CN=RootCA1", CertTools.getSubjectDN(cAChain.get(0)));
            assertEquals("CN=EndEntity1", CertTools.getSubjectDN(val.getCertificate()));
        }
    }

    /**
     * Tests the certificate for EndEntity3 signed by RootCA2.
     * It has a distribution point with an issuer name.
     * The CRLPATHS property is removed which should make the validation fail.
     * Note: If this test fails the CRLPATHS property is not set, which might cause other tests to also fail.
     */
    @Test
    public void test09NoCRLPath() throws Exception {
        String crlPaths = sSSession.getCurrentWorkerConfig(15).getProperty("VAL1.ISSUER2.CRLPATHS");

        sSSession.setWorkerProperty(15, "VAL1.ISSUER2.CRLPATHS", "");
        sSSession.reloadConfiguration(15);

        ValidateRequest req = new ValidateRequest(certEndEntity3, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertNotEquals("Not valid as no CRL should be found", Validation.Status.VALID, val.getStatus());
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=RootCA2", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=EndEntity3", CertTools.getSubjectDN(val.getCertificate()));

        sSSession.setWorkerProperty(15, "VAL1.ISSUER2.CRLPATHS", crlPaths);
        sSSession.reloadConfiguration(15);
    }

    // TODO: Add more tests for the CRLValidator here
    @Test
    public void test99RemoveDatabase() {
        removeWorker(15);
    }
}
