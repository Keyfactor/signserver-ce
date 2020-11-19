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

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.QueryException;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.TokenOutOfSpaceException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.fail;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.SECRET_KEY_PREFIX;

/**
 * System tests for the KeystoreCryptoToken.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class KeystoreCryptoTokenTest extends KeystoreCryptoTokenTestBase {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(KeystoreCryptoTokenTest.class);

    private static final int WORKER_CMS = 30003;
    private static final int CRYPTO_TOKEN = 30103;
    private static final int JKS_CRYPTO_TOKEN = 30104;
    private final String testSecretKeyAlias="testsecretkey";

    private static final String SIGN_KEY_ALIAS = "p12signkey1234";
    private static final String TEST_KEY_ALIAS = "p12testkey1234";
    private static final String KEYSTORE_NAME = "p12testkeystore1234";

    private File keystoreFile;

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    private void setCMSSignerPropertiesCombined(boolean autoActivate) throws Exception {
        // Create keystore
        keystoreFile = File.createTempFile(KEYSTORE_NAME, ".p12");
        FileOutputStream out = null;
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(null, null);
            out = new FileOutputStream(keystoreFile);
            ks.store(out, pin.toCharArray());
        } finally {
            IOUtils.closeQuietly(out);
        }

        // Setup worker
        workerSession.setWorkerProperty(30003, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.CMSSigner");
        workerSession.setWorkerProperty(30003, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, KeystoreCryptoToken.class.getName());
        workerSession.setWorkerProperty(30003, "NAME", "CMSSignerP12");
        workerSession.setWorkerProperty(30003, "KEYSTORETYPE", "PKCS12");
        workerSession.setWorkerProperty(30003, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(30003, "TYPE", "PROCESSABLE");
        workerSession.setWorkerProperty(30003, "KEYSTOREPATH", keystoreFile.getAbsolutePath());
        workerSession.setWorkerProperty(30003, "DEFAULTKEY", SIGN_KEY_ALIAS);
        if (autoActivate) {
            workerSession.setWorkerProperty(30003, "KEYSTOREPASSWORD", pin);
        } else {
            workerSession.removeWorkerProperty(30003, "KEYSTOREPASSWORD");
        }
    }

    private void setCMSSignerPropertiesSeparateToken() throws Exception {
        // Create keystore
        keystoreFile = File.createTempFile(KEYSTORE_NAME, ".p12");
        FileOutputStream out = null;
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(null, null);
            out = new FileOutputStream(keystoreFile);
            ks.store(out, pin.toCharArray());
        } finally {
            IOUtils.closeQuietly(out);
        }

        // Setup crypto token
        workerSession.setWorkerProperty(30103, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(30103, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, KeystoreCryptoToken.class.getName());
        workerSession.setWorkerProperty(30103, "NAME", "TestCryptoTokenP12");
        workerSession.setWorkerProperty(30103, "KEYSTORETYPE", "PKCS12");
        workerSession.setWorkerProperty(30103, "KEYSTOREPATH", keystoreFile.getAbsolutePath());
        workerSession.setWorkerProperty(30103, "DEFAULTKEY", SIGN_KEY_ALIAS);
        //
        workerSession.setWorkerProperty(30103, "KEYSTOREPASSWORD", pin);

        // Setup worker
        workerSession.setWorkerProperty(30003, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.CMSSigner");
        workerSession.setWorkerProperty(30003, "NAME", "CMSSignerP12");
        workerSession.setWorkerProperty(30003, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(30003, "TYPE", "PROCESSABLE");
        workerSession.setWorkerProperty(30003, "CRYPTOTOKEN", "TestCryptoTokenP12");
        workerSession.setWorkerProperty(30003, "DEFAULTKEY", SIGN_KEY_ALIAS);
    }

    /**
     * Tests setting up a CMS Signer, giving it a certificate and sign a file.
     * Using a worker with its own token.
     */
    @Test
    public void testSigning() throws Exception {
        LOG.info("testSigning");
        final int workerId = WORKER_CMS;
        try {
            setCMSSignerPropertiesCombined(true);
            workerSession.reloadConfiguration(workerId);
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", SIGN_KEY_ALIAS, pin.toCharArray());
            workerSession.reloadConfiguration(workerId);

            cmsSigner(workerId);
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }

    /**
     * Tests setting up a CMS Signer, giving it a certificate and sign a file.
     * Using a worker referencing a crypto token.
     */
    @Test
    public void testSigning_separateToken() throws Exception {
        LOG.info("testSigning_separateToken");
        final int workerId = WORKER_CMS;
        final int tokenId = CRYPTO_TOKEN;
        try {
            setCMSSignerPropertiesSeparateToken();
            workerSession.reloadConfiguration(tokenId);
            workerSession.reloadConfiguration(workerId);
            workerSession.generateSignerKey(new WorkerIdentifier(tokenId), "RSA", "1024", SIGN_KEY_ALIAS, pin.toCharArray());
            workerSession.reloadConfiguration(tokenId);

            cmsSigner(workerId);
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
            removeWorker(tokenId);
        }
    }

    @Test
    public void testGenerateKey() throws Exception {
        LOG.info("testGenerateKey");

        final int workerId = WORKER_CMS;
        try {
            setCMSSignerPropertiesCombined(true);
            workerSession.reloadConfiguration(workerId);

            // Add a reference key
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", "somekey123", pin.toCharArray());

            // Check available aliases
            Set<String> aliases1 = getKeyAliases(workerId);

            if (aliases1.isEmpty()) {
                throw new Exception("getKeyAliases is not working or the slot is empty");
            }

            // If the key already exists, try to remove it first
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                workerSession.removeKey(new WorkerIdentifier(workerId), TEST_KEY_ALIAS);
                aliases1 = getKeyAliases(workerId);
            }
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " already exists and removing it failed");
            }

            // Generate a testkey
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());

            // Now expect the new TEST_KEY_ALIAS
            Set<String> expected = new HashSet<>(aliases1);
            expected.add(TEST_KEY_ALIAS);
            Set<String> aliases2 = getKeyAliases(workerId);
            assertEquals("new key added", expected, aliases2);
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }

    /**
     * Test that generating a key with a specified key spec results in the
     * expected public exponent on the public key.
     *
     * @param spec
     * @param expected
     */
    private void testGenerateKeyWithPublicExponent(final String spec,
                                                   final BigInteger expected)
        throws Exception {

        final int workerId = WORKER_CMS;

        try {
            setCMSSignerPropertiesCombined(true);
            workerSession.reloadConfiguration(workerId);

            // Generate a key with a given key spec
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", spec,
                                            "keywithexponent", pin.toCharArray());
            final Collection<KeyTestResult> testResults =
                    workerSession.testKey(new WorkerIdentifier(workerId), "keywithexponent", pin.toCharArray());
            for (final KeyTestResult testResult : testResults) {
                assertTrue("Testkey successful", testResult.isSuccess());
            }

            // Generate CSR, and check the public key's public exponent
            final PKCS10CertReqInfo certReqInfo = new PKCS10CertReqInfo("SHA1WithRSA",
                "CN=test01GenerateKey,C=SE", null);
            AbstractCertReqData data = (AbstractCertReqData) workerSession
                .getCertificateRequest(new WorkerIdentifier(workerId), certReqInfo, false, "keywithexponent");
            final PKCS10CertificationRequest req
                = new PKCS10CertificationRequest(data.toBinaryForm());

            final RSAPublicKey pubKey = (RSAPublicKey) getPublicKeyFromRequest(req);

            assertEquals("Returned public exponent",
                         expected, pubKey.getPublicExponent());
        } finally {
            try {
                workerSession.removeKey(new WorkerIdentifier(workerId), "keywithexponent");
            } catch (SignServerException ignored) {}
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }

    /**
     * Test generating a key with a custom specified public exponent in the spec.
     */
    @Test
    public void testGenerateKeyWithPublicExponentCustom() throws Exception {
        testGenerateKeyWithPublicExponent("2048 exp 5", BigInteger.valueOf(5));
    }

    /**
     * Test generating a key with the default public exponent.
     */
    @Test
    public void testGenerateKeyWithPublicExponentDefault() throws Exception {
        testGenerateKeyWithPublicExponent("2048", BigInteger.valueOf(0x10001));
    }

    /**
     * Tests that key generation is not allowed when the number of keys has
     * reached the KEYGENERATIONLIMIT.
     * Also checks that when allowing for one more keys, the next key can be
     * generated.
     */
    @SuppressWarnings("ThrowableResultIgnored")
    @Test
    public void testKeyGenerationLimit() throws Exception {
        LOG.info("testKeyGenerationLimit");

        final int workerId = WORKER_CMS;
        try {
            setCMSSignerPropertiesCombined(true);
            workerSession.reloadConfiguration(workerId);

            // Add a reference key
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", "somekey123", pin.toCharArray());

            // Check available aliases
            final int keys = getKeyAliases(workerId).size();

            // Set the current number of keys as maximum
            workerSession.setWorkerProperty(workerId, "KEYGENERATIONLIMIT", String.valueOf(keys));
            workerSession.reloadConfiguration(workerId);

            // Key generation should fail
            try {
                workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
                fail("Should have failed because of no space in token");
            } catch (TokenOutOfSpaceException expected) { // NOPMD
                // OK
            }

            // Allow for one more keys to be created
            workerSession.setWorkerProperty(workerId, "KEYGENERATIONLIMIT", String.valueOf(keys + 1));
            workerSession.reloadConfiguration(workerId);

            // Generate a new key
            try {
                workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
            } catch (CryptoTokenOfflineException ex) {
                fail("Should have worked but got: " + ex.getLocalizedMessage());
            }

            final int keys2 = getKeyAliases(workerId).size();
            assertEquals("one more key", keys + 1, keys2);

            // Key generation should fail
            try {
                workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
                fail("Should have failed because of no space in token");
            } catch (TokenOutOfSpaceException expected) { // NOPMD
                // OK
            }
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }

    /**
     * Tests that a worker just set up with a key store containing a new
     * key-pair and is activated manually gets status ACTIVE.
     */
    @Test
    public void testActivateWithNewKeystore() throws Exception {
        LOG.info("testActivateWithNewKeystore");

        final boolean autoActivate = false;

        final int workerId = WORKER_CMS;
        try {
            setCMSSignerPropertiesCombined(autoActivate);

            // Create a key-pair and certificate in the keystore
            FileOutputStream out = null;
            try {
                KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
                ks.load(null, null);

                // Generate key and issue certificate
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
                kpg.initialize(1024);
                final KeyPair keyPair = kpg.generateKeyPair();
                X509Certificate[] chain = new X509Certificate[1];
                chain[0] = getSelfCertificate("CN=TestActivateWithNewKeystore" + ", C=SE", keyPair);
                ks.setKeyEntry("newkey11", keyPair.getPrivate(), pin.toCharArray(), chain);

                out = new FileOutputStream(keystoreFile);
                ks.store(out, pin.toCharArray());
            } finally {
                IOUtils.closeQuietly(out);
            }

            workerSession.setWorkerProperty(workerId, "DEFAULTKEY", "newkey11");
            workerSession.reloadConfiguration(workerId);

            // Activate first so we can generate a key
            workerSession.activateSigner(new WorkerIdentifier(workerId), pin);

            List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
            assertTrue("Fatal errors: " + errors, workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors().isEmpty());

        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }

    /**
     * Test importing a new certificate chain to an existing keystore.
     */
    @Test
    public void testImportCertificateChain() throws Exception {
        LOG.info("testImportCertificateChain");

        final boolean autoActivate = false;

        final int workerId = WORKER_CMS;
        try {
            setCMSSignerPropertiesCombined(autoActivate);

            // Generate key and issue certificate
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(1024);
            final KeyPair keyPair = kpg.generateKeyPair();

            // Create a key-pair and certificate in the keystore
            FileOutputStream out = null;
            try {
                KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
                ks.load(null, null);


                final X509Certificate[] chain = new X509Certificate[1];
                chain[0] = getSelfCertificate("CN=Test", keyPair);
                ks.setKeyEntry("newkey11", keyPair.getPrivate(), pin.toCharArray(), chain);

                out = new FileOutputStream(keystoreFile);
                ks.store(out, pin.toCharArray());
            } finally {
                IOUtils.closeQuietly(out);
            }

            workerSession.setWorkerProperty(workerId, "DEFAULTKEY", "newkey11");
            workerSession.reloadConfiguration(workerId);

            // Activate first so we can generate a key
            workerSession.activateSigner(new WorkerIdentifier(workerId), pin);

            List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
            assertTrue("Fatal errors: " + errors, workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors().isEmpty());

            // generate a new certificate
            final X509Certificate newCert =
                    getSelfCertificate("CN=TestNew", keyPair);

            workerSession.importCertificateChain(new WorkerIdentifier(workerId),
                    Collections.singletonList(newCert.getEncoded()), "newkey11", null);

            final Certificate readCert = workerSession.getSignerCertificate(new WorkerIdentifier(workerId));
            assertArrayEquals("Matching certificates", newCert.getEncoded(), readCert.getEncoded());
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }

    /** Creates a self signed certificate. */
    private X509Certificate getSelfCertificate(String alias, KeyPair keyPair) throws Exception {
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime-24*60*60*1000);
        final Date lastDate = new Date(currentTime + (long) 946080000 * 1000);
        final X509v3CertificateBuilder cg = new JcaX509v3CertificateBuilder(new X500Principal(alias), BigInteger.valueOf(firstDate.getTime()), firstDate, lastDate, new X500Principal(alias), keyPair.getPublic());
        final JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        contentSignerBuilder.setProvider("BC");
        final ContentSigner contentSigner = contentSignerBuilder.build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(cg.build(contentSigner));
    }

    @Test
    public void testGenerateKey_separateToken() throws Exception {
        LOG.info("testGenerateKey_separateToken");

        final int workerId = WORKER_CMS;
        final int tokenId = CRYPTO_TOKEN;
        try {
            setCMSSignerPropertiesSeparateToken();
            workerSession.reloadConfiguration(tokenId);
            workerSession.reloadConfiguration(workerId);

            // Add a reference key
            workerSession.generateSignerKey(new WorkerIdentifier(tokenId), "RSA", "1024", "somekey123", pin.toCharArray());

            // Check available aliases
            Set<String> aliases1 = getKeyAliases(tokenId);

            if (aliases1.isEmpty()) {
                throw new Exception("getKeyAliases is not working or the slot is empty");
            }

            // If the key already exists, try to remove it first
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                workerSession.removeKey(new WorkerIdentifier(tokenId), TEST_KEY_ALIAS);
                aliases1 = getKeyAliases(tokenId);
            }
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " already exists and removing it failed");
            }

            // Generate a testkey
            workerSession.generateSignerKey(new WorkerIdentifier(tokenId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());

            // Now expect the new TEST_KEY_ALIAS
            Set<String> expected = new HashSet<>(aliases1);
            expected.add(TEST_KEY_ALIAS);
            Set<String> aliases2 = getKeyAliases(tokenId);
            assertEquals("new key added", expected, aliases2);

        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
            removeWorker(tokenId);
        }
    }

    @Test
    public void testRemoveKey() throws Exception {
        LOG.info("testRemoveKey");

        final int workerId = WORKER_CMS;
        try {
            setCMSSignerPropertiesCombined(true);
            workerSession.reloadConfiguration(workerId);

            // Add a reference key
            workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", "somekey123", pin.toCharArray());

            // Check available aliases
            Set<String> aliases1 = getKeyAliases(workerId);

            if (aliases1.isEmpty()) {
                throw new Exception("getKeyAliases is not working or the slot is empty");
            }

            if (!aliases1.contains(TEST_KEY_ALIAS)) {
                // Generate a testkey
                workerSession.generateSignerKey(new WorkerIdentifier(workerId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
                aliases1 = getKeyAliases(workerId);
            }
            if (!aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " did not exist and it could not be created");
            }
            workerSession.reloadConfiguration(workerId);

            // Remove the key
            workerSession.removeKey(new WorkerIdentifier(workerId), TEST_KEY_ALIAS);

            // Now expect the TEST_KEY_ALIAS to have been removed
            Set<String> aliases2 = getKeyAliases(workerId);
            Set<String> expected = new HashSet<>(aliases1);
            expected.remove(TEST_KEY_ALIAS);
            assertEquals("new key removed", expected, aliases2);
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }

    @Test
    public void testRemoveKey_separateToken() throws Exception {
        LOG.info("testRemoveKey_separateToken");

        final int workerId = WORKER_CMS;
        final int tokenId = CRYPTO_TOKEN;
        try {
            setCMSSignerPropertiesSeparateToken();
            workerSession.reloadConfiguration(tokenId);
            workerSession.reloadConfiguration(workerId);

            // Add a reference key
            workerSession.generateSignerKey(new WorkerIdentifier(tokenId), "RSA", "1024", "somekey123", pin.toCharArray());

            // Check available aliases
            Set<String> aliases1 = getKeyAliases(tokenId);

            if (aliases1.isEmpty()) {
                throw new Exception("getKeyAliases is not working or the slot is empty");
            }

            if (!aliases1.contains(TEST_KEY_ALIAS)) {
                // Generate a testkey
                workerSession.generateSignerKey(new WorkerIdentifier(tokenId), "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
                aliases1 = getKeyAliases(tokenId);
            }
            if (!aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " did not exist and it could not be created");
            }
            workerSession.reloadConfiguration(tokenId);

            // Remove the key
            workerSession.removeKey(new WorkerIdentifier(tokenId), TEST_KEY_ALIAS);

            // Now expect the TEST_KEY_ALIAS to have been removed
            Set<String> aliases2 = getKeyAliases(tokenId);
            Set<String> expected = new HashSet<>(aliases1);
            expected.remove(TEST_KEY_ALIAS);
            assertEquals("new key removed", expected, aliases2);
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
            removeWorker(tokenId);
        }
    }

    /**
     * Test that omitting KEYSTORETYPE gives a correct error message.
     */
    @Test
    public void testNoKeystoreType() throws Exception {
       LOG.info("testNoKeystoreType");

       final int workerId = WORKER_CMS;

       try {
           setCMSSignerPropertiesCombined(true);
           workerSession.removeWorkerProperty(workerId, "KEYSTORETYPE");
           workerSession.reloadConfiguration(workerId);

           final List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
           assertTrue("Should contain error",
                   errors.contains("Failed to initialize crypto token: Missing KEYSTORETYPE property"));
       } finally {
           FileUtils.deleteQuietly(keystoreFile);
           removeWorker(workerId);
       }
    }

    /**
     * Test that setting an unknown KEYSTORETYPE gives a correct error message.
     */
    @Test
    public void testUnknownKeystoreType() throws Exception {
       LOG.info("testNoKeystoreType");

       final int workerId = WORKER_CMS;

       try {
           setCMSSignerPropertiesCombined(true);
           workerSession.setWorkerProperty(workerId, "KEYSTORETYPE", "FOOBAR");
           workerSession.reloadConfiguration(workerId);

           final List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
           assertTrue("Should contain error",
                   errors.contains("Failed to initialize crypto token: KEYSTORETYPE should be either PKCS12, JKS, or INTERNAL"));
       } finally {
           FileUtils.deleteQuietly(keystoreFile);
           removeWorker(workerId);
       }
    }

    /**
     * Test that omitting KEYSTOREPATH results in a config error.
     */
    @Test
    public void testMissingKeystorePath() throws Exception {
        LOG.info("testMissingKeystorePath");

        final int workerId = WORKER_CMS;

        try {
            setCMSSignerPropertiesCombined(true);
            workerSession.removeWorkerProperty(workerId, "KEYSTOREPATH");
            workerSession.reloadConfiguration(workerId);

            final List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
            assertTrue("Should contain error",
                    errors.contains("Failed to initialize crypto token: Missing KEYSTOREPATH property"));
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }

    /**
     * Test that setting KEYSTOREPATH not pointing an existing file results in a config error.
     */
    @Test
    public void testUnknownKeystorePath() throws Exception {
        LOG.info("testMissingKeystorePath");

        final int workerId = WORKER_CMS;

        try {
            setCMSSignerPropertiesCombined(true);
            workerSession.setWorkerProperty(workerId, "KEYSTOREPATH", "non-existing.p12");
            workerSession.reloadConfiguration(workerId);

            final List<String> errors = workerSession.getStatus(new WorkerIdentifier(workerId)).getFatalErrors();
            assertTrue("Should contain error",
                    errors.contains("Failed to initialize crypto token: File not found: non-existing.p12"));
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }

    /**
     * Test that unsetting DEFAULTKEY results in a CryptoTokenOfflineException.
     */
    @Test
    public void testNoDefaultKey() {
        LOG.info("testNoDefaultKey");

        final int workerId = WORKER_CMS;

        try {
            setCMSSignerPropertiesCombined(true);
            // unset DEFAULTKEY
            workerSession.removeWorkerProperty(workerId, "DEFAULTKEY");
            workerSession.reloadConfiguration(workerId);

            cmsSigner(workerId);
        } catch (CryptoTokenOfflineException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }

    private void setP12CryptoTokenProperties() throws Exception {
        // Create keystore
        keystoreFile = File.createTempFile(KEYSTORE_NAME, ".p12");
        FileOutputStream out = null;
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
            ks.load(null, null);
            out = new FileOutputStream(keystoreFile);
            ks.store(out, pin.toCharArray());
        } finally {
            IOUtils.closeQuietly(out);
        }

        // Setup crypto token
        workerSession.setWorkerProperty(KeystoreCryptoTokenTest.JKS_CRYPTO_TOKEN, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(KeystoreCryptoTokenTest.JKS_CRYPTO_TOKEN, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, KeystoreCryptoToken.class.getName());
        workerSession.setWorkerProperty(KeystoreCryptoTokenTest.JKS_CRYPTO_TOKEN, "NAME", "TestJKSCryptoTokenP12");
        workerSession.setWorkerProperty(KeystoreCryptoTokenTest.JKS_CRYPTO_TOKEN, "KEYSTORETYPE", "PKCS12");
        workerSession.setWorkerProperty(KeystoreCryptoTokenTest.JKS_CRYPTO_TOKEN, "TYPE", "PROCESSABLE");
        workerSession.setWorkerProperty(KeystoreCryptoTokenTest.JKS_CRYPTO_TOKEN, "KEYSTOREPATH", keystoreFile.getAbsolutePath());
        //
        workerSession.setWorkerProperty(KeystoreCryptoTokenTest.JKS_CRYPTO_TOKEN, "KEYSTOREPASSWORD", pin);
    }

    /**
     * Tests AES secret key generation loading a PKS12 CryptoToken and changing KEYSTOREYPTE Type to JKS.
     */
    @Test
    public void testGenerateSecretKey_AES_256_JKSTypeP12CryptoToken() throws Exception {
        LOG.info("testGenerateSecretKey_AES_256_JKSTypeP12CryptoToken");
        secretKeyGenerationHelper("AES", "256");
    }

    /**
     * Tests DES secret key generation loading a PKS12 CryptoToken and changing KEYSTOREYPTE Type to JKS.
     */
    @Test
    public void testGenerateSecretKey_DES_56_JKSTypeP12CryptoToken() throws Exception {
        LOG.info("testGenerateSecretKey_DES_56_JKSTypeP12CryptoToken");
        secretKeyGenerationHelper("DES", "56");
    }

    /**
     * Tests Blowfish secret key generation loading a PKS12 CryptoToken and changing KEYSTOREYPTE Type to JKS.
     */
    @Test
    public void testGenerateSecretKey_Blowfish_168_JKSTypeP12CryptoToken() throws Exception {
        LOG.info("testGenerateSecretKey_Blowfish_168_JKSTypeP12CryptoToken");
        secretKeyGenerationHelper(SECRET_KEY_PREFIX + "Blowfish", "168");
    }

    private void secretKeyGenerationHelper(String algo, String spec) throws Exception {
        try {
            setP12CryptoTokenProperties();
            workerSession.reloadConfiguration(JKS_CRYPTO_TOKEN);

            // Add a reference key
            generateKey("RSA", "1024", "somekey123");

            workerSession.setWorkerProperty(JKS_CRYPTO_TOKEN, "KEYSTORETYPE", "JKS");
            workerSession.reloadConfiguration(JKS_CRYPTO_TOKEN);

            removeExisting();
            generateKey(algo, spec, testSecretKeyAlias);
            findNewEntry();
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(JKS_CRYPTO_TOKEN);
        }
    }

    private void removeExisting() throws CryptoTokenOfflineException, OperationUnsupportedException, QueryException, AuthorizationDeniedException, InvalidWorkerIdException, InvalidAlgorithmParameterException, SignServerException, KeyStoreException, UnsupportedCryptoTokenParameter {
        TokenSearchResults searchResults = searchTokenEntries(QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), "testsecretkey")));
        List<TokenEntry> entries = searchResults.getEntries();
        if (!entries.isEmpty()) {
            destroyKey();
        }
    }

    private void findNewEntry() throws CryptoTokenOfflineException, OperationUnsupportedException, QueryException, AuthorizationDeniedException, InvalidWorkerIdException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        TokenSearchResults searchResults = searchTokenEntries(QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), "testsecretkey")));
        List<TokenEntry> entries = searchResults.getEntries();
        assertEquals(1, entries.size());
    }

    private TokenSearchResults searchTokenEntries(QueryCriteria qc) throws OperationUnsupportedException, CryptoTokenOfflineException, QueryException, InvalidWorkerIdException, AuthorizationDeniedException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        return getWorkerSession().searchTokenEntries(new WorkerIdentifier(JKS_CRYPTO_TOKEN), 0, 1, qc, true, Collections.emptyMap());
    }

    private void generateKey(String keyType, String keySpec, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        getWorkerSession().generateSignerKey(new WorkerIdentifier(JKS_CRYPTO_TOKEN), keyType, keySpec, alias, null);
    }

    private void destroyKey() throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException, KeyStoreException {
        getWorkerSession().removeKey(new WorkerIdentifier(JKS_CRYPTO_TOKEN), "testsecretkey");
    }
}
