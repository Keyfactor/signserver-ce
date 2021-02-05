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

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.jce.X509KeyUsage;
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
import static org.junit.Assert.assertNull;

/**
 * TODO: Document me!
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ValidationServiceWorkerTest extends ModulesTestCase {

    private static final int WORKER_DUMMY = 15;
    private static final int WORKER_NOREVOCATION = 16;

    private static WorkerSessionRemote sSSession = null;
    private final ProcessSessionRemote processSession = getProcessSession();

    private static X509Certificate validRootCA1;
    private static X509Certificate validSubCA1;
    private static X509Certificate validCert1;
    private static X509Certificate revokedCert1;
    private static X509Certificate expiredCert1;
    private static X509Certificate noYetValidCert1;
    private static X509Certificate badSigCert1;
    private static X509Certificate expiredRootCA1;
    private static X509Certificate certByExpiredRoot;
    private static X509Certificate notYetValidCA;
    private static X509Certificate certByNotYetValidSub;
    private static X509Certificate revocedRootCA1;
    private static X509Certificate certByRevocedRoot;
    private static X509Certificate validSubCA2;
    private static X509Certificate validSubSubCA2;
    private static X509Certificate validSubSubSubCA2;
    private static X509Certificate validSubSubSubSubCA2;
    private static X509Certificate certSignedByLongChain;
    private static X509Certificate identificationCert1;
    private static X509Certificate esigCert1;
    private static X509Certificate badKeyUsageCert1;

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        sSSession = ServiceLocator.getInstance().lookupRemote(WorkerSessionRemote.class);
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        KeyPair validRootCA1Keys = KeyTools.genKeys("1024", "RSA");
        validRootCA1 = ValidationTestUtils.genCert("CN=ValidRootCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validRootCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

        KeyPair validSubCA1Keys = KeyTools.genKeys("1024", "RSA");
        validSubCA1 = ValidationTestUtils.genCert("CN=ValidSubCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validSubCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

        KeyPair validCert1Keys = KeyTools.genKeys("1024", "RSA");
        validCert1 = ValidationTestUtils.genCert("CN=ValidCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);
        revokedCert1 = ValidationTestUtils.genCert("CN=revokedCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);
        expiredCert1 = ValidationTestUtils.genCert("CN=expiredCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() - 1000000), false);
        noYetValidCert1 = ValidationTestUtils.genCert("CN=noYetValidCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(System.currentTimeMillis() + 1000000), new Date(System.currentTimeMillis() + 2000000), false);
        badSigCert1 = ValidationTestUtils.genCert("CN=badSigCert1", "CN=ValidSubCA1", validRootCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);

        identificationCert1 = ValidationTestUtils.genCert("CN=identificationCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false, X509KeyUsage.digitalSignature + X509KeyUsage.keyEncipherment);
        esigCert1 = ValidationTestUtils.genCert("CN=esigCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false, X509KeyUsage.nonRepudiation);
        badKeyUsageCert1 = ValidationTestUtils.genCert("CN=badKeyUsageCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false, X509KeyUsage.dataEncipherment + X509KeyUsage.cRLSign);

        KeyPair expiredRootCA1Keys = KeyTools.genKeys("1024", "RSA");
        expiredRootCA1 = ValidationTestUtils.genCert("CN=expiredRootCA1", "CN=expiredRootCA1", expiredRootCA1Keys.getPrivate(), expiredRootCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() - 1000000), true);

        certByExpiredRoot = ValidationTestUtils.genCert("CN=certByExpiredRoot", "CN=expiredRootCA1", expiredRootCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);

        KeyPair notYetValidSubCA1Keys = KeyTools.genKeys("1024", "RSA");
        notYetValidCA = ValidationTestUtils.genCert("CN=notYetValidCA", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), notYetValidSubCA1Keys.getPublic(), new Date(System.currentTimeMillis() + 1000000), new Date(System.currentTimeMillis() + 2000000), true);

        certByNotYetValidSub = ValidationTestUtils.genCert("CN=certByNotYetValidSub", "CN=notYetValidCA", notYetValidSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);

        KeyPair revocedRootCA1Keys = KeyTools.genKeys("1024", "RSA");
        revocedRootCA1 = ValidationTestUtils.genCert("CN=revocedRootCA1", "CN=revocedRootCA1", revocedRootCA1Keys.getPrivate(), revocedRootCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);
        certByRevocedRoot = ValidationTestUtils.genCert("CN=certByRevocedRoot", "CN=revocedRootCA1", revocedRootCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);


        KeyPair validSubCA2Keys = KeyTools.genKeys("1024", "RSA");
        validSubCA2 = ValidationTestUtils.genCert("CN=ValidSubCA2", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validSubCA2Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);
        KeyPair validSubSubCA2Keys = KeyTools.genKeys("1024", "RSA");
        validSubSubCA2 = ValidationTestUtils.genCert("CN=ValidSubSubCA2", "CN=ValidSubCA2", validSubCA2Keys.getPrivate(), validSubSubCA2Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);
        KeyPair validSubSubSubCA2Keys = KeyTools.genKeys("1024", "RSA");
        validSubSubSubCA2 = ValidationTestUtils.genCert("CN=ValidSubSubSubCA2", "CN=ValidSubSubCA2", validSubSubCA2Keys.getPrivate(), validSubSubSubCA2Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);
        KeyPair validSubSubSubSubCA2Keys = KeyTools.genKeys("1024", "RSA");
        validSubSubSubSubCA2 = ValidationTestUtils.genCert("CN=ValidSubSubSubSubCA2", "CN=ValidSubSubSubCA2", validSubSubSubCA2Keys.getPrivate(), validSubSubSubSubCA2Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

        certSignedByLongChain = ValidationTestUtils.genCert("CN=certSignedByLongChain", "CN=ValidSubSubSubSubCA2", validSubSubSubSubCA2Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);

        ArrayList<X509Certificate> validChain1 = new ArrayList<>();
        // Add in the wrong order
        validChain1.add(validRootCA1);
        validChain1.add(validSubCA1);

        ArrayList<X509Certificate> expiredRootChain = new ArrayList<>();
        expiredRootChain.add(expiredRootCA1);

        ArrayList<X509Certificate> notYetValidSubChain = new ArrayList<>();
        notYetValidSubChain.add(notYetValidCA);
        notYetValidSubChain.add(validRootCA1);

        ArrayList<X509Certificate> revocedRootCA1Chain = new ArrayList<>();
        revocedRootCA1Chain.add(revocedRootCA1);

        ArrayList<X509Certificate> longChain = new ArrayList<>();
        longChain.add(validSubCA2);
        longChain.add(validSubSubSubCA2);
        longChain.add(validRootCA1);
        longChain.add(validSubSubSubSubCA2);
        longChain.add(validSubSubCA2);

        // Worker 15 - DummyValidator
        sSSession.setWorkerProperty(15, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        sSSession.setWorkerProperty(15, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.validationservice.server.ValidationServiceWorker");
        sSSession.setWorkerProperty(15, "AUTHTYPE", "NOAUTH");
        sSSession.setWorkerProperty(15, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
        sSSession.setWorkerProperty(15, "VAL1.TESTPROP", "TEST");
        sSSession.setWorkerProperty(15, "VAL1.ISSUER1.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(validChain1));
        sSSession.setWorkerProperty(15, "VAL1.ISSUER2.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(expiredRootChain));
        sSSession.setWorkerProperty(15, "VAL1.ISSUER4.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(notYetValidSubChain));
        sSSession.setWorkerProperty(15, "VAL2.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
        sSSession.setWorkerProperty(15, "VAL2.TESTPROP", "TEST");
        sSSession.setWorkerProperty(15, "VAL2.ISSUER1.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(revocedRootCA1Chain));
        sSSession.setWorkerProperty(15, "VAL2.ISSUER250.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(longChain));
        sSSession.reloadConfiguration(15);

        // Worker 16 - NoRevokationCheckingValidator
        sSSession.setWorkerProperty(16, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        sSSession.setWorkerProperty(16, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.validationservice.server.ValidationServiceWorker");
        sSSession.setWorkerProperty(16, "AUTHTYPE", "NOAUTH");
        sSSession.setWorkerProperty(16, "VAL1.CLASSPATH", "org.signserver.validationservice.server.NoRevocationCheckingValidator");
        sSSession.setWorkerProperty(16, "VAL1.ISSUER1.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(validChain1));
        sSSession.setWorkerProperty(16, "VAL1.ISSUER2.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(expiredRootChain));
        sSSession.setWorkerProperty(16, "VAL1.ISSUER4.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(notYetValidSubChain));
        sSSession.setWorkerProperty(16, "VAL2.CLASSPATH", "org.signserver.validationservice.server.NoRevocationCheckingValidator");
        sSSession.setWorkerProperty(16, "VAL2.ISSUER1.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(revocedRootCA1Chain));
        sSSession.setWorkerProperty(16, "VAL2.ISSUER250.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(longChain));
        sSSession.reloadConfiguration(16);
    }

    @Test
    public void test01BasicValidation() throws Exception {
        basicValidation(WORKER_DUMMY);
    }

    @Test
    public void test01BasicValidationNoRevocationChecking() throws Exception {
        basicValidation(WORKER_NOREVOCATION);
    }

    private void basicValidation(final int workerId) throws Exception {
        ValidateRequest req = new ValidateRequest(validCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.VALID);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));
    }

    @Test
    public void test02RevokedCertificate() throws Exception {
        ValidateRequest req = new ValidateRequest(revokedCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.REVOKED);
        assertNotNull(val.getStatusMessage());
        assertEquals(3, val.getRevokationReason());
        assertNotNull(val.getRevokedDate());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));

    }

    @Test
    public void test03ExpiredCertificate() throws Exception {
        expiredCertificate(WORKER_DUMMY);
    }

    @Test
    public void test03ExpiredCertificateNoRevocation() throws Exception {
        expiredCertificate(WORKER_NOREVOCATION);
    }

    private void expiredCertificate(final int workerId) throws Exception {
        ValidateRequest req = new ValidateRequest(expiredCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.EXPIRED);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));
    }

    @Test
    public void test04NotYetValidCertificate() throws Exception {
        notYetValidCertificate(WORKER_DUMMY);
    }

    @Test
    public void test04NotYetValidCertificateNoRevocation() throws Exception {
        notYetValidCertificate(WORKER_NOREVOCATION);
    }

    private void notYetValidCertificate(final int workerId) throws Exception {
        ValidateRequest req = new ValidateRequest(noYetValidCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.NOTYETVALID);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));
    }

    @Test
    public void test05BadSignatureCertificate() throws Exception {
        badSignatureCertificate(WORKER_DUMMY);
    }

    @Test
    public void test05BadSignatureCertificateNoRevocation() throws Exception {
        badSignatureCertificate(WORKER_NOREVOCATION);
    }

    private void badSignatureCertificate(final int workerId) throws Exception {
        ValidateRequest req = new ValidateRequest(badSigCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.DONTVERIFY);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));
    }

    @Test
    public void test06signedByExpiredRootCertificate() throws Exception {
        signedByExpiredRootCertificate(WORKER_DUMMY);
    }

    @Test
    public void test06signedByExpiredRootCertificateNoRevocation() throws Exception {
        signedByExpiredRootCertificate(WORKER_NOREVOCATION);
    }

    private void signedByExpiredRootCertificate(final int workerId) throws Exception {
        ValidateRequest req = new ValidateRequest(certByExpiredRoot, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.CAEXPIRED);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=expiredRootCA1", CertTools.getSubjectDN(cAChain.get(0)));
    }

    @Test
    public void test07signedByNotYetValidSubCA() throws Exception {
        signedByNotYetValidSubCA(WORKER_DUMMY);
    }

    @Test
    public void test07signedByNotYetValidSubCANoRevocation() throws Exception {
        signedByNotYetValidSubCA(WORKER_NOREVOCATION);
    }

    private void signedByNotYetValidSubCA(final int workerId) throws Exception {
        ValidateRequest req = new ValidateRequest(certByNotYetValidSub, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.CANOTYETVALID);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=notYetValidCA", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));
    }

    @Test
    public void test09signedByRevocedRootCA() throws Exception {
        ValidateRequest req = new ValidateRequest(certByRevocedRoot, null);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.CAREVOKED);
        assertNotNull(val.getStatusMessage());
        assertNotNull(val.getRevokedDate());
        assertEquals(3, val.getRevokationReason());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=revocedRootCA1", CertTools.getSubjectDN(cAChain.get(0)));
    }

    @Test
    public void test10LongChainValidation() throws Exception {
        longChainValidation(WORKER_DUMMY);
    }

    @Test
    public void test10LongChainValidationNoRevocation() throws Exception {
        longChainValidation(WORKER_NOREVOCATION);
    }

    private void longChainValidation(final int workerId) throws Exception {
        ValidateRequest req = new ValidateRequest(certSignedByLongChain, null);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.VALID);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubSubSubSubCA2", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidSubSubSubCA2", CertTools.getSubjectDN(cAChain.get(1)));
        assertEquals("CN=ValidSubSubCA2", CertTools.getSubjectDN(cAChain.get(2)));
        assertEquals("CN=ValidSubCA2", CertTools.getSubjectDN(cAChain.get(3)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(4)));
    }

    @Test
    public void test11CertPurpose() throws Exception {
        certPurpose(WORKER_DUMMY);
    }

    @Test
    public void test11CertPurposeNoRevocation() throws Exception {
        certPurpose(WORKER_NOREVOCATION);
    }

    private void certPurpose(final int workerId) throws Exception {
        ValidateRequest req = new ValidateRequest(identificationCert1, ValidationServiceConstants.CERTPURPOSE_IDENTIFICATION);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.VALID);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));

        req = new ValidateRequest(identificationCert1, ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
        res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.VALID); // digitalSignature is OK
        assertNotNull(val.getStatusMessage());
        cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));

        req = new ValidateRequest(esigCert1, ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
        res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.VALID);
        assertNotNull(res.getValidCertificatePurposes());
        assertEquals(res.getValidCertificatePurposes(), ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
        assertNotNull(val.getStatusMessage());
        cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));

        req = new ValidateRequest(esigCert1, ValidationServiceConstants.CERTPURPOSE_IDENTIFICATION);
        res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.BADCERTPURPOSE);
        assertNull(res.getValidCertificatePurposes());
        assertNotNull(val.getStatusMessage());
        cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));

        req = new ValidateRequest(badKeyUsageCert1, ValidationServiceConstants.CERTPURPOSE_IDENTIFICATION);
        res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.BADCERTPURPOSE);
        assertNotNull(val.getStatusMessage());
        cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));

        req = new ValidateRequest(badKeyUsageCert1, ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
        res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.BADCERTPURPOSE);
        assertNotNull(val.getStatusMessage());
        cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));

        req = new ValidateRequest(validCert1, ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
        res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.BADCERTPURPOSE);
        assertNotNull(val.getStatusMessage());
        cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));

        req = new ValidateRequest(identificationCert1, ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE + "," + ValidationServiceConstants.CERTPURPOSE_IDENTIFICATION);
        res = (ValidateResponse) processSession.process(new WorkerIdentifier(workerId), req, new RemoteRequestContext());

        val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.VALID);
        assertEquals(res.getValidCertificatePurposes(), ValidationServiceConstants.CERTPURPOSE_IDENTIFICATION);
    }

    @Test
    public void test12CertificateCache() throws Exception {
        sSSession.setWorkerProperty(15, "VAL1.WAITTIME", "1000");
        sSSession.setWorkerProperty(15, "CACHEDISSUERS", "CN=ValidSubCA1;CN=revocedRootCA1");
        sSSession.reloadConfiguration(15);


        ValidateRequest req = new ValidateRequest(validCert1, null);
        ValidateResponse res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

        Validation val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.VALID);
        assertNotNull(val.getStatusMessage());
        List<Certificate> cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));

        res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());
        Validation val2 = res.getValidation();
        assertNotNull(val2);
        assertEquals(val2.getStatus(), Validation.Status.VALID);
        assertNotNull(val2.getStatusMessage());
        assertEquals(val.getValidationDate(), val2.getValidationDate());
        cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubCA1", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(1)));

        req = new ValidateRequest(certSignedByLongChain, null);
        res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

        val = res.getValidation();
        assertNotNull(val);
        assertEquals(val.getStatus(), Validation.Status.VALID);
        assertNotNull(val.getStatusMessage());
        cAChain = val.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubSubSubSubCA2", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidSubSubSubCA2", CertTools.getSubjectDN(cAChain.get(1)));
        assertEquals("CN=ValidSubSubCA2", CertTools.getSubjectDN(cAChain.get(2)));
        assertEquals("CN=ValidSubCA2", CertTools.getSubjectDN(cAChain.get(3)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(4)));

        res = (ValidateResponse) processSession.process(new WorkerIdentifier(15), req, new RemoteRequestContext());

        val2 = res.getValidation();
        assertNotNull(val2);
        assertEquals(val2.getStatus(), Validation.Status.VALID);
        assertNotNull(val2.getStatusMessage());
        assertNotEquals(val.getValidationDate(), val2.getValidationDate());
        cAChain = val2.getCAChain();
        assertNotNull(cAChain);
        assertEquals("CN=ValidSubSubSubSubCA2", CertTools.getSubjectDN(cAChain.get(0)));
        assertEquals("CN=ValidSubSubSubCA2", CertTools.getSubjectDN(cAChain.get(1)));
        assertEquals("CN=ValidSubSubCA2", CertTools.getSubjectDN(cAChain.get(2)));
        assertEquals("CN=ValidSubCA2", CertTools.getSubjectDN(cAChain.get(3)));
        assertEquals("CN=ValidRootCA1", CertTools.getSubjectDN(cAChain.get(4)));
    }

    @Test
    public void test99RemoveDatabase() throws Exception {
        removeWorker(15);
        removeWorker(16);
    }
}
