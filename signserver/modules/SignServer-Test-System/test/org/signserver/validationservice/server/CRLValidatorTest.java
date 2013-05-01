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
import junit.framework.TestCase;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.jce.X509KeyUsage;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.ValidationServiceConstants;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for the CRL Validator.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CRLValidatorTest {

    private static IGlobalConfigurationSession.IRemote gCSession;
    private static IWorkerSession.IRemote sSSession;
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

        gCSession = ServiceLocator.getInstance().lookupRemote(
                IGlobalConfigurationSession.IRemote.class);
        sSSession = ServiceLocator.getInstance().lookupRemote(
                IWorkerSession.IRemote.class);

        String envSignServerHome = System.getenv("SIGNSERVER_HOME");
        assertNotNull("Environment variable SIGNSERVER_HOME must be set!", envSignServerHome);
        signServerHome = new File(envSignServerHome);
        assertTrue(signServerHome.exists());
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        // Setup keys, certificates and CRLs: RootCA1
        File cdpFile1 = new File(signServerHome, "tmp" + File.separator + "rootca1.crl");
        URL cdpUrl1 = cdpFile1.toURI().toURL();
        CRLDistPoint crlDistPointCA1WithUrl = ValidationTestUtils.generateDistPointWithUrl(cdpUrl1);
        ArrayList<X509Certificate> chain1 = new ArrayList<X509Certificate>();

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

        ArrayList<RevokedCertInfo> revoked = new ArrayList<RevokedCertInfo>();
        revoked.add(new RevokedCertInfo("fingerprint", certEndEntity2.getSerialNumber(), new Date(),
                RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED, new Date(System.currentTimeMillis() + 1000000)));

        crlRootCA1 = ValidationTestUtils.genCRL(certRootCA1, keysRootCA1.getPrivate(), crlDistPointCA1WithUrl.getDistributionPoints()[0], revoked, 24, 1);

        // Write CRL to file
        OutputStream out = null;
        try {
            out = new FileOutputStream(cdpFile1);
            out.write(crlRootCA1.getEncoded());
        } finally {
            if (out != null) {
                out.close();
            }
        }
        assertTrue(cdpFile1.exists());
        assertTrue(cdpFile1.canRead());
        chain1.add(certRootCA1);

        // Setup keys, certificates and CRLs: RootCA2
        File cdpFile2 = new File(signServerHome, "tmp" + File.separator + "rootca2.crl");
        URL cdpUrl2 = cdpFile2.toURI().toURL();
        CRLDistPoint crlDistPointCA2WithIssuer = ValidationTestUtils.generateDistPointWithIssuer("CN=RootCA2");
        ArrayList<X509Certificate> chain2 = new ArrayList<X509Certificate>();

        KeyPair keysRootCA2 = KeyTools.genKeys("1024", "RSA");
        certRootCA2 = ValidationTestUtils.genCert("CN=RootCA2", "CN=RootCA2", keysRootCA2.getPrivate(), keysRootCA2.getPublic(),
                new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

        KeyPair keysEndEntity3 = KeyTools.genKeys("1024", "RSA");
        certEndEntity3 = ValidationTestUtils.genCert("CN=EndEntity3", "CN=RootCA2", keysRootCA2.getPrivate(), keysEndEntity3.getPublic(),
                new Date(0), new Date(System.currentTimeMillis() + 1000000), false, 0, crlDistPointCA2WithIssuer);

        KeyPair keysEndEntity4 = KeyTools.genKeys("1024", "RSA");
        certEndEntity4 = ValidationTestUtils.genCert("CN=EndEntity4", "CN=RootCA2", keysRootCA2.getPrivate(), keysEndEntity4.getPublic(),
                new Date(0), new Date(System.currentTimeMillis() + 1000000), false, 0, crlDistPointCA2WithIssuer);

        ArrayList<RevokedCertInfo> revoked2 = new ArrayList<RevokedCertInfo>();
        revoked2.add(new RevokedCertInfo("fingerprint2", certEndEntity4.getSerialNumber(), new Date(),
                RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED, new Date(System.currentTimeMillis() + 1000000)));

        crlRootCA2 = ValidationTestUtils.genCRL(certRootCA2, keysRootCA2.getPrivate(), crlDistPointCA2WithIssuer.getDistributionPoints()[0], revoked2, 24, 1);

        // Write CRL to file
        OutputStream out2 = null;
        try {
            out2 = new FileOutputStream(cdpFile2);
            out2.write(crlRootCA2.getEncoded());
        } finally {
            if (out2 != null) {
                out2.close();
            }
        }
        assertTrue(cdpFile2.exists());
        assertTrue(cdpFile2.canRead());
        chain2.add(certRootCA2);

        // Setup worker
        gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER15.CLASSPATH", "org.signserver.validationservice.server.ValidationServiceWorker");
        gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER15.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");
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
        ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());

        Validation val = res.getValidation();
        assertTrue(val != null);
        assertTrue(val.getStatus().equals(Validation.Status.VALID));
        assertTrue(val.getStatusMessage() != null);
        List<Certificate> cAChain = val.getCAChain();
        assertTrue(cAChain != null);
        assertTrue(CertTools.getSubjectDN(cAChain.get(0)).equals("CN=RootCA1"));
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
        ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());

        Validation val = res.getValidation();
        assertTrue(val != null);

        // Note: The best would be if we could get REVOKED as status from the CRLValidator and could then test with:
        //assertEquals(Validation.Status.REVOKED, val.getStatus());
        assertFalse(Validation.Status.VALID.equals(val.getStatus()));

        assertTrue(val.getStatusMessage() != null);
        List<Certificate> cAChain = val.getCAChain();
        assertTrue(cAChain != null);
        assertTrue(CertTools.getSubjectDN(cAChain.get(0)).equals("CN=RootCA1"));
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
        ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());

        Validation val = res.getValidation();
        assertTrue(val != null);
        assertTrue(val.getStatus().equals(Validation.Status.VALID));
        assertTrue(val.getStatusMessage() != null);
        List<Certificate> cAChain = val.getCAChain();
        assertTrue(cAChain != null);
        assertTrue(CertTools.getSubjectDN(cAChain.get(0)).equals("CN=RootCA2"));
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
        ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());

        Validation val = res.getValidation();
        assertTrue(val != null);

        // Note: The best would be if we could get REVOKED as status from the CRLValidator and could then test with:
        //assertEquals(Validation.Status.REVOKED, val.getStatus());
        assertFalse(Validation.Status.VALID.equals(val.getStatus()));

        assertTrue(val.getStatusMessage() != null);
        List<Certificate> cAChain = val.getCAChain();
        assertTrue(cAChain != null);
        assertTrue(CertTools.getSubjectDN(cAChain.get(0)).equals("CN=RootCA2"));
        assertEquals("CN=EndEntity4", CertTools.getSubjectDN(val.getCertificate()));
    }

    /**
     * Tests the certificate for EndEntity5 signed by RootCA1.
     * The certificate is expired.
     */
    @Test
    public void test05Expired() throws Exception {
        ValidateRequest req = new ValidateRequest(certEndEntity5Expired, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());

        Validation val = res.getValidation();
        assertTrue(val != null);
        assertFalse("certificate should be expired", val.getStatus().equals(Validation.Status.VALID));
        assertTrue(val.getStatusMessage() != null);
        List<Certificate> cAChain = val.getCAChain();
        assertTrue(cAChain != null);
        assertTrue(CertTools.getSubjectDN(cAChain.get(0)).equals("CN=RootCA1"));
        assertEquals("CN=EndEntity5", CertTools.getSubjectDN(val.getCertificate()));
    }

    /**
     * Tests the certificate for EndEntity6 signed by RootCA1.
     * The certificate is not yet valid.
     */
    @Test
    public void test06NotYetValid() throws Exception {
        ValidateRequest req = new ValidateRequest(certEndEntity6NotYetValid, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());

        Validation val = res.getValidation();
        assertTrue(val != null);
        assertFalse("certificate should not be valid yet", val.getStatus().equals(Validation.Status.VALID));
        assertTrue(val.getStatusMessage() != null);
        List<Certificate> cAChain = val.getCAChain();
        assertTrue(cAChain != null);
        assertTrue(CertTools.getSubjectDN(cAChain.get(0)).equals("CN=RootCA1"));
        assertEquals("CN=EndEntity6", CertTools.getSubjectDN(val.getCertificate()));
    }

    /**
     * Tests the certificate for EndEntity7 signed by RootCA1.
     * The certificate is not valid as it is not signed width the right issuers key
     */
    @Test
    public void test07WrongIssuer() throws Exception {
        ValidateRequest req = new ValidateRequest(certEndEntity7WrongIssuer, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());

        Validation val = res.getValidation();
        assertTrue(val != null);
        assertFalse("certificate should not be valid", val.getStatus().equals(Validation.Status.VALID));
        assertTrue(val.getStatusMessage() != null);
        List<Certificate> cAChain = val.getCAChain();
        assertTrue(cAChain != null);
        assertTrue(CertTools.getSubjectDN(cAChain.get(0)).equals("CN=RootCA1"));
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
            ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());

            Validation val = res.getValidation();
            assertTrue(val != null);
            assertTrue("certificate should be valid for electronic signature", val.getStatus().equals(Validation.Status.VALID));
            assertTrue(val.getStatusMessage() != null);
            List<Certificate> cAChain = val.getCAChain();
            assertTrue(cAChain != null);
            assertTrue(CertTools.getSubjectDN(cAChain.get(0)).equals("CN=RootCA1"));
            assertEquals("CN=EndEntity8", CertTools.getSubjectDN(val.getCertificate()));
        }

        // Second: test one certificate without CERTPURPOSE_ELECTRONIC_SIGNATURE and see that it fails
        {
            ValidateRequest req = new ValidateRequest(certEndEntity1, ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
            ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());

            Validation val = res.getValidation();
            assertTrue(val != null);
            assertFalse("certificate should fail is it does not have keyusage sig", val.getStatus().equals(Validation.Status.VALID));
            assertTrue(val.getStatusMessage() != null);
            List<Certificate> cAChain = val.getCAChain();
            assertTrue(cAChain != null);
            assertTrue(CertTools.getSubjectDN(cAChain.get(0)).equals("CN=RootCA1"));
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
        ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertFalse("Not valid as no CRL should be found", Validation.Status.VALID.equals(val.getStatus()));
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertTrue(CertTools.getSubjectDN(cAChain.get(0)).equals("CN=RootCA2"));
        assertEquals("CN=EndEntity3", CertTools.getSubjectDN(val.getCertificate()));

        sSSession.setWorkerProperty(15, "VAL1.ISSUER2.CRLPATHS", crlPaths);
        sSSession.reloadConfiguration(15);
    }

    // TODO: Add more tests for the CRLValidator here
    @Test
    public void test99RemoveDatabase() throws Exception {
        gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER15.CLASSPATH");
        gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER15.SIGNERTOKEN.CLASSPATH");

        sSSession.removeWorkerProperty(15, "AUTHTYPE");
        sSSession.removeWorkerProperty(15, "VAL1.CLASSPATH");
        sSSession.removeWorkerProperty(15, "VAL1.ISSUER1.CERTCHAIN");
        sSSession.removeWorkerProperty(15, "VAL1.ISSUER1.CRLPATHS");
        sSSession.removeWorkerProperty(15, "VAL1.ISSUER2.CERTCHAIN");
        sSSession.removeWorkerProperty(15, "VAL1.ISSUER2.CRLPATHS");

        sSSession.reloadConfiguration(15);
    }
}
