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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import static junit.framework.TestCase.assertEquals;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.KeyTestResult;
import org.signserver.common.SignServerUtil;
import org.signserver.common.TokenOutOfSpaceException;

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
    
    private static final String SIGN_KEY_ALIAS = "p12signkey1234";
    private static final String TEST_KEY_ALIAS = "p12testkey1234";
    private static final String KEYSTORE_NAME = "p12testkeystore1234";
    
    private File keystoreFile;
 
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }
    
    private void setCMSSignerPropertiesCombined(final int workerId, boolean autoActivate) throws Exception {
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
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".CLASSPATH", "org.signserver.module.cmssigner.CMSSigner");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", KeystoreCryptoToken.class.getName());
        workerSession.setWorkerProperty(workerId, "NAME", "CMSSignerP12");
        workerSession.setWorkerProperty(workerId, "KEYSTORETYPE", "PKCS12");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "KEYSTOREPATH", keystoreFile.getAbsolutePath());
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", SIGN_KEY_ALIAS);
        if (autoActivate) {
            workerSession.setWorkerProperty(workerId, "KEYSTOREPASSWORD", pin);
        } else {
            workerSession.removeWorkerProperty(workerId, "KEYSTOREPASSWORD");
        }
    }

    private void setCMSSignerPropertiesSeparateToken(final int workerId, final int tokenId, boolean autoActivate) throws Exception {
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
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + tokenId + ".CLASSPATH", "org.signserver.server.signers.CryptoWorker");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + tokenId + ".SIGNERTOKEN.CLASSPATH", KeystoreCryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", "TestCryptoTokenP12");
        workerSession.setWorkerProperty(tokenId, "KEYSTORETYPE", "PKCS12");
        workerSession.setWorkerProperty(tokenId, "KEYSTOREPATH", keystoreFile.getAbsolutePath());
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", SIGN_KEY_ALIAS);   
        if (autoActivate) {
            workerSession.setWorkerProperty(tokenId, "KEYSTOREPASSWORD", pin);
        } else {
            workerSession.removeWorkerProperty(workerId, "KEYSTOREPASSWORD");
        }

        // Setup worker
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".CLASSPATH", "org.signserver.module.cmssigner.CMSSigner");
        workerSession.setWorkerProperty(workerId, "NAME", "CMSSignerP12");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", "TestCryptoTokenP12");
        workerSession.setWorkerProperty(workerId, "DEFAULTKEY", SIGN_KEY_ALIAS);
    }

    /**
     * Tests setting up a CMS Signer, giving it a certificate and sign a file.
     * Using a worker with its own token.
     */
    public void testSigning() throws Exception {
        LOG.info("testSigning");
        final int workerId = WORKER_CMS;
        try {
            setCMSSignerPropertiesCombined(workerId, true);
            workerSession.reloadConfiguration(workerId);
            workerSession.generateSignerKey(workerId, "RSA", "1024", SIGN_KEY_ALIAS, pin.toCharArray());
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
    public void testSigning_separateToken() throws Exception {
        LOG.info("testSigning_separateToken");
        final int workerId = WORKER_CMS;
        final int tokenId = CRYPTO_TOKEN;
        try {
            setCMSSignerPropertiesSeparateToken(workerId, tokenId, true);
            workerSession.reloadConfiguration(tokenId);
            workerSession.reloadConfiguration(workerId);
            workerSession.generateSignerKey(tokenId, "RSA", "1024", SIGN_KEY_ALIAS, pin.toCharArray());
            workerSession.reloadConfiguration(tokenId);

            cmsSigner(workerId);
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
            removeWorker(tokenId);
        }
    }
    
    public void testGenerateKey() throws Exception {
        LOG.info("testGenerateKey");
        
        final int workerId = WORKER_CMS;
        try {
            setCMSSignerPropertiesCombined(workerId, true);
            workerSession.reloadConfiguration(workerId);
            
            // Add a reference key
            workerSession.generateSignerKey(workerId, "RSA", "1024", "somekey123", pin.toCharArray());
            
            // Check available aliases
            Set<String> aliases1 = getKeyAliases(workerId);
            
            if (aliases1.isEmpty()) {
                throw new Exception("getKeyAliases is not working or the slot is empty");
            }
            
            // If the key already exists, try to remove it first
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                workerSession.removeKey(workerId, TEST_KEY_ALIAS);
                aliases1 = getKeyAliases(workerId);
            }
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " already exists and removing it failed");
            }

            // Generate a testkey
            workerSession.generateSignerKey(workerId, "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
            
            // Now expect the new TEST_KEY_ALIAS
            Set<String> expected = new HashSet<String>(aliases1);
            expected.add(TEST_KEY_ALIAS);
            Set<String> aliases2 = getKeyAliases(workerId);
            assertEquals("new key added", expected, aliases2);
            
            // Generate a key with a custom RSA public exponent
            workerSession.generateSignerKey(workerId, "RSA", "2048 exp 5", 
                                            "keywithexponent", pin.toCharArray());
            final Collection<KeyTestResult> testResults =
                    workerSession.testKey(workerId, "keywithexponent", pin.toCharArray());
            for (final KeyTestResult testResult : testResults) {
                assertTrue("Testkey successful", testResult.isSuccess());
            }
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }
    
    /**
     * Tests that key generation is not allowed when the number of keys has
     * reached the KEYGENERATIONLIMIT.
     * Also checks that when allowing for one more keys, the next key can be
     * generated.
     */
    @SuppressWarnings("ThrowableResultIgnored")
    public void testKeyGenerationLimit() throws Exception {
        LOG.info("testKeyGenerationLimit");
        
        final int workerId = WORKER_CMS;
        try {
            setCMSSignerPropertiesCombined(workerId, true);
            workerSession.reloadConfiguration(workerId);
            
            // Add a reference key
            workerSession.generateSignerKey(workerId, "RSA", "1024", "somekey123", pin.toCharArray());
            
            // Check available aliases
            final int keys = getKeyAliases(workerId).size();
            
            // Set the current number of keys as maximum
            workerSession.setWorkerProperty(workerId, "KEYGENERATIONLIMIT", String.valueOf(keys));
            workerSession.reloadConfiguration(workerId);
            
            // Key generation should fail
            try {
                workerSession.generateSignerKey(workerId, "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
                fail("Should have failed because of no space in token");
            } catch (TokenOutOfSpaceException expected) { // NOPMD
                // OK
            }
            
            // Allow for one more keys to be created
            workerSession.setWorkerProperty(workerId, "KEYGENERATIONLIMIT", String.valueOf(keys + 1));
            workerSession.reloadConfiguration(workerId);
            
            // Generate a new key
            try {
                workerSession.generateSignerKey(workerId, "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
            } catch (CryptoTokenOfflineException ex) {
                fail("Should have worked but got: " + ex.getLocalizedMessage());
            }
            
            final int keys2 = getKeyAliases(workerId).size();
            assertEquals("one more key", keys + 1, keys2);
            
            // Key generation should fail
            try {
                workerSession.generateSignerKey(workerId, "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
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
     * @throws Exception
     */
    public void testActivateWithNewKeystore() throws Exception {
        LOG.info("testActivateWithNewKeystore");

        final boolean autoActivate = false;

        final int workerId = WORKER_CMS;
        try {
            setCMSSignerPropertiesCombined(workerId, autoActivate);

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
                chain[0] = getSelfCertificate("CN=TestActivateWithNewKeystore" + ", C=SE", (long) 30*24*60*60*365, keyPair);
                ks.setKeyEntry("newkey11", keyPair.getPrivate(), pin.toCharArray(), chain);

                out = new FileOutputStream(keystoreFile);
                ks.store(out, pin.toCharArray());
            } finally {
                IOUtils.closeQuietly(out);
            }

            workerSession.setWorkerProperty(workerId, "DEFAULTKEY", "newkey11");
            workerSession.reloadConfiguration(workerId);

            // Activate first so we can generate a key
            workerSession.activateSigner(workerId, pin);

            List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
            assertTrue("Fatal errors: " + errors, workerSession.getStatus(workerId).getFatalErrors().isEmpty());

        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }

    /**
     * Test importing a new certificate chain to an existing keystore.
     * @throws Exception 
     */
    public void testImportCertificateChain() throws Exception {
        LOG.info("testImportCertificateChain");

        final boolean autoActivate = false;

        final int workerId = WORKER_CMS;
        try {
            setCMSSignerPropertiesCombined(workerId, autoActivate);

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
                chain[0] = getSelfCertificate("CN=Test", (long) 30*24*60*60*365, keyPair);
                ks.setKeyEntry("newkey11", keyPair.getPrivate(), pin.toCharArray(), chain);

                out = new FileOutputStream(keystoreFile);
                ks.store(out, pin.toCharArray());
            } finally {
                IOUtils.closeQuietly(out);
            }

            workerSession.setWorkerProperty(workerId, "DEFAULTKEY", "newkey11");
            workerSession.reloadConfiguration(workerId);

            // Activate first so we can generate a key
            workerSession.activateSigner(workerId, pin);

            List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
            assertTrue("Fatal errors: " + errors, workerSession.getStatus(workerId).getFatalErrors().isEmpty());
            
            // generate a new certificate
            final X509Certificate newCert =
                    getSelfCertificate("CN=TestNew", (long) 30*24*60*60*365, keyPair);
            
            workerSession.importCertificateChain(workerId,
                    Arrays.asList(newCert.getEncoded()), "newkey11", null);
            
            final Certificate readCert = workerSession.getSignerCertificate(workerId);
            assertTrue("Matching certificates", Arrays.equals(newCert.getEncoded(), readCert.getEncoded()));
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }
    
    /** Creates a self signed certificate. */
    private X509Certificate getSelfCertificate(String alias, long validity, KeyPair keyPair) throws Exception {
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime-24*60*60*1000);
        final Date lastDate = new Date(currentTime + validity * 1000);
        final X509v3CertificateBuilder cg = new JcaX509v3CertificateBuilder(new X500Principal(alias), BigInteger.valueOf(firstDate.getTime()), firstDate, lastDate, new X500Principal(alias), keyPair.getPublic());
        final JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
        contentSignerBuilder.setProvider("BC");
        final ContentSigner contentSigner = contentSignerBuilder.build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(cg.build(contentSigner));
    }

    public void testGenerateKey_separateToken() throws Exception {
        LOG.info("testGenerateKey_separateToken");

        final int workerId = WORKER_CMS;
        final int tokenId = CRYPTO_TOKEN;
        try {
            setCMSSignerPropertiesSeparateToken(workerId, tokenId, true);
            workerSession.reloadConfiguration(tokenId);
            workerSession.reloadConfiguration(workerId);

            // Add a reference key
            workerSession.generateSignerKey(tokenId, "RSA", "1024", "somekey123", pin.toCharArray());

            // Check available aliases
            Set<String> aliases1 = getKeyAliases(tokenId);

            if (aliases1.isEmpty()) {
                throw new Exception("getKeyAliases is not working or the slot is empty");
            }

            // If the key already exists, try to remove it first
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                workerSession.removeKey(tokenId, TEST_KEY_ALIAS);
                aliases1 = getKeyAliases(tokenId);
            }
            if (aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " already exists and removing it failed");
            }

            // Generate a testkey
            workerSession.generateSignerKey(tokenId, "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());

            // Now expect the new TEST_KEY_ALIAS
            Set<String> expected = new HashSet<String>(aliases1);
            expected.add(TEST_KEY_ALIAS);
            Set<String> aliases2 = getKeyAliases(tokenId);
            assertEquals("new key added", expected, aliases2);

        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
            removeWorker(tokenId);
        }
    }

    public void testRemoveKey() throws Exception {
        LOG.info("testRemoveKey");
        
        final int workerId = WORKER_CMS;
        try {
            setCMSSignerPropertiesCombined(workerId, true);
            workerSession.reloadConfiguration(workerId);
            
            // Add a reference key
            workerSession.generateSignerKey(workerId, "RSA", "1024", "somekey123", pin.toCharArray());
            
            // Check available aliases
            Set<String> aliases1 = getKeyAliases(workerId);

            if (aliases1.isEmpty()) {
                throw new Exception("getKeyAliases is not working or the slot is empty");
            }
            
            if (!aliases1.contains(TEST_KEY_ALIAS)) {
                // Generate a testkey
                workerSession.generateSignerKey(workerId, "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
                aliases1 = getKeyAliases(workerId);
            }
            if (!aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " did not exist and it could not be created");
            }
            workerSession.reloadConfiguration(workerId);
            
            // Remove the key
            workerSession.removeKey(workerId, TEST_KEY_ALIAS);
            
            // Now expect the TEST_KEY_ALIAS to have been removed
            Set<String> aliases2 = getKeyAliases(workerId);
            Set<String> expected = new HashSet<String>(aliases1);
            expected.remove(TEST_KEY_ALIAS);
            assertEquals("new key removed", expected, aliases2);
        } finally {
            FileUtils.deleteQuietly(keystoreFile);
            removeWorker(workerId);
        }
    }

    public void testRemoveKey_separateToken() throws Exception {
        LOG.info("testRemoveKey_separateToken");

        final int workerId = WORKER_CMS;
        final int tokenId = CRYPTO_TOKEN;
        try {
            setCMSSignerPropertiesSeparateToken(workerId, tokenId, true);
            workerSession.reloadConfiguration(tokenId);
            workerSession.reloadConfiguration(workerId);

            // Add a reference key
            workerSession.generateSignerKey(tokenId, "RSA", "1024", "somekey123", pin.toCharArray());

            // Check available aliases
            Set<String> aliases1 = getKeyAliases(tokenId);

            if (aliases1.isEmpty()) {
                throw new Exception("getKeyAliases is not working or the slot is empty");
            }

            if (!aliases1.contains(TEST_KEY_ALIAS)) {
                // Generate a testkey
                workerSession.generateSignerKey(tokenId, "RSA", "1024", TEST_KEY_ALIAS, pin.toCharArray());
                aliases1 = getKeyAliases(tokenId);
            }
            if (!aliases1.contains(TEST_KEY_ALIAS)) {
                throw new Exception("Pre-condition failed: Key with alias " + TEST_KEY_ALIAS + " did not exist and it could not be created");
            }
            workerSession.reloadConfiguration(tokenId);

            // Remove the key
            workerSession.removeKey(tokenId, TEST_KEY_ALIAS);

            // Now expect the TEST_KEY_ALIAS to have been removed
            Set<String> aliases2 = getKeyAliases(tokenId);
            Set<String> expected = new HashSet<String>(aliases1);
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
     * 
     * @throws Exception
     */
    public void testNoKeystoreType() throws Exception {
       LOG.info("testNoKeystoreType");
       
       final int workerId = WORKER_CMS;
       
       try {
           setCMSSignerPropertiesCombined(workerId, true);
           workerSession.removeWorkerProperty(workerId, "KEYSTORETYPE");
           workerSession.reloadConfiguration(workerId);
           
           final List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
           assertTrue("Should contain error",
                   errors.contains("Failed to initialize crypto token: Missing KEYSTORETYPE property"));
       } finally {
           removeWorker(workerId);
       }
    }
    
    /**
     * Test that setting an unknown KEYSTORETYPE gives a correct error message.
     * 
     * @throws Exception
     */
    public void testUnknownKeystoreType() throws Exception {
       LOG.info("testNoKeystoreType");
       
       final int workerId = WORKER_CMS;
       
       try {
           setCMSSignerPropertiesCombined(workerId, true);
           workerSession.setWorkerProperty(workerId, "KEYSTORETYPE", "FOOBAR");
           workerSession.reloadConfiguration(workerId);
           
           final List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
           assertTrue("Should contain error",
                   errors.contains("Failed to initialize crypto token: KEYSTORETYPE should be either PKCS12, JKS, or INTERNAL"));
       } finally {
           removeWorker(workerId);
       }
    }
    
    /**
     * Test that omitting KEYSTOREPATH results in a config error.
     * 
     * @throws Exception
     */
    public void testMissingKeystorePath() throws Exception {
        LOG.info("testMissingKeystorePath");
        
        final int workerId = WORKER_CMS;
        
        try {
            setCMSSignerPropertiesCombined(workerId, true);
            workerSession.removeWorkerProperty(workerId, "KEYSTOREPATH");
            workerSession.reloadConfiguration(workerId);
            
            final List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
            assertTrue("Should contain error",
                    errors.contains("Failed to initialize crypto token: Missing KEYSTOREPATH property"));
        } finally {
            removeWorker(workerId);
        }
    }
    
    /**
     * Test that setting KEYSTOREPATH not pointing an existing file results in a config error.
     * 
     * @throws Exception
     */
    public void testUnknownKeystorePath() throws Exception {
        LOG.info("testMissingKeystorePath");
        
        final int workerId = WORKER_CMS;
        
        try {
            setCMSSignerPropertiesCombined(workerId, true);
            workerSession.setWorkerProperty(workerId, "KEYSTOREPATH", "non-existing.p12");
            workerSession.reloadConfiguration(workerId);
            
            final List<String> errors = workerSession.getStatus(workerId).getFatalErrors();
            assertTrue("Should contain error",
                    errors.contains("Failed to initialize crypto token: File not found: non-existing.p12"));
        } finally {
            removeWorker(workerId);
        }
    }
    
    /**
     * Test that unsetting DEFAULTKEY results in a CryptoTokenOfflineException.
     * 
     * @throws Exception 
     */
    public void testNoDefaultKey() throws Exception {
        LOG.info("testNoDefaultKey");
        
        final int workerId = WORKER_CMS;
        
        try {
            setCMSSignerPropertiesCombined(workerId, true);
            // unset DEFAULTKEY
            workerSession.removeWorkerProperty(workerId, "DEFAULTKEY");
            workerSession.reloadConfiguration(workerId);
            
            cmsSigner(workerId);
        } catch (CryptoTokenOfflineException e) {
            // expected
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        } finally {
            removeWorker(workerId);
        }
    }
}
