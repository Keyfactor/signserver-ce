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
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.Collection;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.util.Base64;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.SignServerUtil;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.common.ServiceLocator;
import org.signserver.common.KeyTestResult;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Tests for any Signer.
 *
 * Can be used for testing key generation, key testing, csr generation etc.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class TestAnySigner extends TestCase {

    private static final Logger LOG = Logger.getLogger(TestAnySigner.class);

    /** WORKERID used in this test case as defined in 
     * junittest-part-config.properties for XMLSigner. */
    private static final int WORKERID = 5803;

    private static IWorkerSession.IRemote workerSession;
    private static String signserverhome;
    private static int moduleVersion;

    private static File keystoreFile;
	
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        workerSession = ServiceLocator.getInstance().lookupRemote(
                IWorkerSession.IRemote.class);
        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
        TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull("Please set SIGNSERVER_HOME environment variable", signserverhome);
        CommonAdminInterface.BUILDMODE = "SIGNSERVER";
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
    }	
	
    public void test00SetupDatabase() throws Exception {

        final MARFileParser marFileParser = new MARFileParser(signserverhome
                + "/dist-server/xmlsigner.mar");
        moduleVersion = marFileParser.getVersionFromMARFile();

        TestUtils.assertSuccessfulExecution(new String[] {
                "module",
                "add",
                signserverhome + "/dist-server/xmlsigner.mar",
                "junittest"
            });
        assertTrue("Loading module",
                TestUtils.grepTempOut("Loading module XMLSIGNER"));
        assertTrue("Module loaded",
                TestUtils.grepTempOut("Module loaded successfully."));

        workerSession.reloadConfiguration(WORKERID);

        final File newKeystore = new File(signserverhome + File.separator + "tmp"
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

    public void test01GenerateKey() throws Exception {

        final char[] authCode = "foo123".toCharArray();
        final String newKeyAlias = "newkey0001";

        final String actualNewAlias = workerSession.generateSignerKey(WORKERID, "RSA",
                "2048", newKeyAlias, authCode);
        
        assertEquals("alias", newKeyAlias, actualNewAlias);

        final Collection<KeyTestResult> results = workerSession.testKey(WORKERID,
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
                "CN=test01GenerateKey", null);
        Base64SignerCertReqData data = (Base64SignerCertReqData) workerSession
                .getCertificateRequest(WORKERID, certReqInfo, false);
        byte[] reqBytes = data.getBase64CertReq();
        final PKCS10CertificationRequest req
                = new PKCS10CertificationRequest(Base64.decode(reqBytes));

        final PublicKey actualPubKey = req.getPublicKey();

        assertEquals("key in request", pubKey, actualPubKey);
    }

    public void test99TearDownDatabase() throws Exception {
        TestUtils.assertSuccessfulExecution(new String[] {
            "removeworker",
            String.valueOf(WORKERID)
        });

        TestUtils.assertSuccessfulExecution(new String[] {
            "module",
            "remove",
            "XMLSIGNER",
            String.valueOf(moduleVersion)
        });
        assertTrue("module remove",
                TestUtils.grepTempOut("Removal of module successful."));
        workerSession.reloadConfiguration(WORKERID);
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
