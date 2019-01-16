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
package org.signserver.module.xmlsigner;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.util.Collection;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.KeyTestResult;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.SignServerUtil;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSession;

/**
 * Tests for any Signer.
 *
 * Can be used for testing key generation, key testing, csr generation etc.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class AnySignerTest extends ModulesTestCase {

    private static final int WORKERID = 5803;    
    private static final int[] WORKERS = new int[] {WORKERID};

    private static File signserverhome;

    private static File keystoreFile;

    private final WorkerSession workerSession = getWorkerSession();
    
    @Before
    @Override
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        signserverhome = PathUtil.getAppHome();
    }

    @After
    @Override
    public void tearDown() throws Exception {
        TestingSecurityManager.remove();
    }	

    @Test
    public void test00SetupDatabase() throws Exception {
        addDummySigner(WORKERID, "TestXMLSignerKeystore2", true);

        final File newKeystore = new File(signserverhome, "tmp"
                + File.separator + "empty-testkeystore.p12");
        if (newKeystore.exists()) {
            assertTrue(newKeystore.delete());
        }

        KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
        keystore.load(null, null);
        keystore.store(new FileOutputStream(newKeystore), 
                "foo123".toCharArray());

        assertTrue("Exists new keystore: " + newKeystore.getAbsolutePath(),
                newKeystore.exists());

        // Update path to keystore file
        workerSession.setWorkerProperty(WORKERID, "KEYSTOREPATH",
                newKeystore.getAbsolutePath());
        workerSession.reloadConfiguration(WORKERID);

        keystoreFile = newKeystore;
    }

    @Test
    public void test01GenerateKey() throws Exception {

        final char[] authCode = "foo123".toCharArray();
        final String newKeyAlias = "newkey0001";

        final String actualNewAlias = workerSession.generateSignerKey(new WorkerIdentifier(WORKERID), "RSA",
                "2048", newKeyAlias, authCode);
        
        assertEquals("alias", newKeyAlias, actualNewAlias);

        final Collection<KeyTestResult> results = workerSession.testKey(new WorkerIdentifier(WORKERID),
                newKeyAlias, authCode);
        final KeyTestResult result = results.iterator().next();
        assertEquals("alias in result", newKeyAlias, result.getAlias());
        assertTrue("test result", result.isSuccess());

        final KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(keystoreFile), authCode);
        final PublicKey pubKey = keyStore.getCertificate(newKeyAlias)
                .getPublicKey();
        final byte[] pubKeyBytes = pubKey.getEncoded();
        final String expectedKeyHash = createKeyHash(pubKeyBytes);
        final String actualKeyHash = result.getPublicKeyHash();
        
        assertEquals("key hash", expectedKeyHash, actualKeyHash);

        // Set new key as NEXTCERTSIGNKEY
        workerSession.setWorkerProperty(WORKERID, "NEXTCERTSIGNKEY", newKeyAlias);
        workerSession.reloadConfiguration(WORKERID);
        
        // Generate CSR
        final PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA",
                "CN=test01GenerateKey,C=SE", null);
        Base64SignerCertReqData data = (Base64SignerCertReqData) workerSession
                .getCertificateRequest(new WorkerIdentifier(WORKERID), certReqInfo, false, false);
        byte[] reqBytes = data.getBase64CertReq();
        final PKCS10CertificationRequest req
                = new PKCS10CertificationRequest(Base64.decode(reqBytes));

        final PublicKey actualPubKey = getPublicKeyFromRequest(req);

        assertEquals("key in request", pubKey, actualPubKey);
        
        // Test that the DN is in the correct order
        String actualDN = req.getSubject().toString();
        assertTrue("dn: " + actualDN, actualDN.startsWith("CN=test01GenerateKey") && actualDN.endsWith("C=SE"));
    }

    /**
     * Test key generation of a ECDSA curve.
     * @throws Exception in case of error
     */
    @Test
    public void test02GenerateKeyECDSA() throws Exception {

        final char[] authCode = "foo123".toCharArray();
        final String newKeyAlias = "newkey0002";

        final String actualNewAlias = workerSession.generateSignerKey(new WorkerIdentifier(WORKERID), 
                "ECDSA", "secp256r1", newKeyAlias, authCode);

        assertEquals("alias", newKeyAlias, actualNewAlias);

        final Collection<KeyTestResult> results = workerSession.testKey(new WorkerIdentifier(WORKERID),
                newKeyAlias, authCode);
        final KeyTestResult result = results.iterator().next();
        assertEquals("alias in result", newKeyAlias, result.getAlias());
        assertTrue("test result", result.isSuccess());

        final KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(keystoreFile), authCode);
        final PublicKey pubKey = keyStore.getCertificate(newKeyAlias)
                .getPublicKey();
        final byte[] pubKeyBytes = pubKey.getEncoded();
        final String expectedKeyHash = createKeyHash(pubKeyBytes);
        final String actualKeyHash = result.getPublicKeyHash();

        assertEquals("keyAlg", "EC", pubKey.getAlgorithm());

        assertEquals("key hash", expectedKeyHash, actualKeyHash);

        // Set new key as NEXTCERTSIGNKEY
        workerSession.setWorkerProperty(WORKERID, "NEXTCERTSIGNKEY", newKeyAlias);
        workerSession.reloadConfiguration(WORKERID);

        // Generate CSR
        final PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo(
                "SHA1WithECDSA", "CN=test02GenerateKey", null);
        Base64SignerCertReqData data = (Base64SignerCertReqData) workerSession
                .getCertificateRequest(new WorkerIdentifier(WORKERID), certReqInfo, false, false);
        byte[] reqBytes = data.getBase64CertReq();
        final PKCS10CertificationRequest req
                = new PKCS10CertificationRequest(Base64.decode(reqBytes));

        final PublicKey actualPubKey = getPublicKeyFromRequest(req);

        assertEquals("key in request", pubKey, actualPubKey);
    }

    @Test
    public void test03GenerateRequestNamedCurve() throws Exception {

        final boolean explicitEcc = false;

        // Generate CSR
        final PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo(
                "SHA1WithECDSA", "CN=test02GenerateKey", null);
        Base64SignerCertReqData data = (Base64SignerCertReqData) workerSession
                .getCertificateRequest(new WorkerIdentifier(WORKERID), certReqInfo, explicitEcc,
                false);
        byte[] reqBytes = data.getBase64CertReq();
        final PKCS10CertificationRequest req
                = new PKCS10CertificationRequest(Base64.decode(reqBytes));

        final PublicKey actualPubKey = getPublicKeyFromRequest(req);
        final PublicKey afterConvert = ECKeyUtil.publicToExplicitParameters(
                actualPubKey, "BC");

        // The following assertion assumes that publicToExplicitParameters
        // returns a new/different PublicKey instance if it was not already
        // converted and if it already was explicit the same instance was
        // returned

        // Not the same object
        assertNotSame("Not converted to explicit",
                actualPubKey.hashCode(), afterConvert.hashCode());
    }

    @Test
    public void test04GenerateRequestExplicitParams() throws Exception {
        final boolean explicitEcc = true;

        // Generate CSR
        final PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo(
                "SHA1WithECDSA", "CN=test02GenerateKey", null);
        Base64SignerCertReqData data = (Base64SignerCertReqData) workerSession
                .getCertificateRequest(new WorkerIdentifier(WORKERID), certReqInfo, explicitEcc,
                false);
        byte[] reqBytes = data.getBase64CertReq();
        final PKCS10CertificationRequest req
                = new PKCS10CertificationRequest(Base64.decode(reqBytes));

        final PublicKey actualPubKey = getPublicKeyFromRequest(req);
        final PublicKey afterConvert = ECKeyUtil.publicToExplicitParameters(
                actualPubKey, "BC");

        // The following assertion assumes that publicToExplicitParameters
        // returns a new/different PublicKey instance if it was not already
        // converted and if it already was explicit the same instance was
        // returned

        // The same object
        assertTrue("Not converted to explicit",
                actualPubKey.hashCode() == afterConvert.hashCode());
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        for (int workerId : WORKERS) {
            removeWorker(workerId);
        }
    }

    public static String createKeyHash(byte[] key) {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA1", "BC");
            final String res = new String(
                    Hex.encode(md.digest(key)));
            md.reset();
            return res;
        } catch (NoSuchProviderException ex) {
            final String message
                    = "Nu such provider trying to hash public key";
            throw new RuntimeException(message, ex);
        } catch (NoSuchAlgorithmException ex) {
            final String message
                    = "Nu such algorithm trying to hash public key";
            throw new RuntimeException(message, ex);
        }
    }
}
