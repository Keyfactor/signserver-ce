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

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test cases for the keystore crypto token storing the keystore in the config.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class KeystoreInConfigCryptoTokenTest extends KeystoreCryptoTokenTestBase {
    private static final Logger LOG =
            Logger.getLogger(KeystoreInConfigCryptoTokenTest.class);

    private static final int WORKER_CMS = 30003;
    private static final int CRYPTO_TOKEN = 30103;

    private static final String SIGN_KEY_ALIAS = "p12signkey1234";
    private static final String TEST_KEY_ALIAS = "p12testkey1234";

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    private void setCMSSignerPropertiesSeparateToken() {
        // Setup crypto token
        workerSession.setWorkerProperty(30103, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(30103, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(30103, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, KeystoreInConfigCryptoToken.class.getName());
        workerSession.setWorkerProperty(30103, "NAME", "TestCryptoTokenInConfig");
        //
        workerSession.setWorkerProperty(30103, "KEYSTOREPASSWORD", pin);

        workerSession.setWorkerProperty(30103, "DEFAULTKEY", SIGN_KEY_ALIAS);

        // Setup worker
        workerSession.setWorkerProperty(30003, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(30003, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.cmssigner.CMSSigner");
        workerSession.setWorkerProperty(30003, "NAME", "CMSSignerConfigToken");
        workerSession.setWorkerProperty(30003, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(30003, "CRYPTOTOKEN", "TestCryptoTokenInConfig");
        workerSession.setWorkerProperty(30003, "DEFAULTKEY", SIGN_KEY_ALIAS);
    }

    /**
     * Tests setting up a CMS Signer, giving it a certificate and sign a file
     */
    @Test
    public void testSigning() throws Exception {
        LOG.info("testSigning");
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
            removeWorker(workerId);
            removeWorker(tokenId);
        }
    }

    /**
     * Test generating an additional key.
     */
    @Test
    public void testGenerateKey() throws Exception {
        LOG.info("testGenerateKey");

        final int workerId = WORKER_CMS;
        final int tokenId = CRYPTO_TOKEN;

        try {
            setCMSSignerPropertiesSeparateToken();

            workerSession.reloadConfiguration(tokenId);
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
            removeWorker(workerId);
            removeWorker(tokenId);
        }
    }

    /**
     * Test removing a key.
     */
    @Test
    public void testRemoveKey() throws Exception {
        LOG.info("testRemoveKey");

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
            assertTrue("removeKey result", workerSession.removeKey(new WorkerIdentifier(tokenId), TEST_KEY_ALIAS));

            // Now expect the TEST_KEY_ALIAS to have been removed
            Set<String> aliases2 = getKeyAliases(tokenId);
            Set<String> expected = new HashSet<>(aliases1);
            expected.remove(TEST_KEY_ALIAS);
            assertEquals("new key removed", expected, aliases2);
        } finally {
            removeWorker(workerId);
            removeWorker(tokenId);
        }
    }

    /**
     * Test testing keys.
     */
    @Test
    public void testTestKey() throws Exception {
        LOG.info("testRemoveKey_separateToken");

        final int workerId = WORKER_CMS;
        final int tokenId = CRYPTO_TOKEN;
        try {
            setCMSSignerPropertiesSeparateToken();
            workerSession.reloadConfiguration(tokenId);
            workerSession.reloadConfiguration(workerId);

            // Add a reference key
            workerSession.generateSignerKey(new WorkerIdentifier(tokenId), "RSA", "1024", "somekey123", pin.toCharArray());
            workerSession.reloadConfiguration(tokenId);

            Collection<KeyTestResult> testResult;

            // test key with "all"
            testResult = workerSession.testKey(new WorkerIdentifier(tokenId), "all", pin.toCharArray());
            assertEquals("Number of keys tested", 1, testResult.size());

            KeyTestResult result = testResult.iterator().next();
            assertTrue("Success testing key", result.isSuccess());
            assertEquals("Testing correct alias", "somekey123", result.getAlias());

            // test key with explicit alias
            testResult = workerSession.testKey(new WorkerIdentifier(tokenId), "somekey123", pin.toCharArray());
            assertEquals("Number of keys tested", 1, testResult.size());

            result = testResult.iterator().next();
            assertTrue("Success testing key", result.isSuccess());
            assertEquals("Testing correct alias", "somekey123", result.getAlias());

            // Add additional key
            workerSession.generateSignerKey(new WorkerIdentifier(tokenId), "RSA", "1024", "anotherkey", pin.toCharArray());
            workerSession.reloadConfiguration(tokenId);

            // test key with "all"
            testResult = workerSession.testKey(new WorkerIdentifier(tokenId), "all", pin.toCharArray());
            assertEquals("Number of keys tested", 2, testResult.size());

            for (final KeyTestResult keyTestResult : testResult) {
                assertTrue("success testing key", keyTestResult.isSuccess());
            }

            // test key with explicit alias
            testResult = workerSession.testKey(new WorkerIdentifier(tokenId), "anotherkey", pin.toCharArray());
            assertEquals("Number of keys tested", 1, testResult.size());

            result = testResult.iterator().next();
            assertTrue("Success testing key", result.isSuccess());
            assertEquals("Testing correct alias", "anotherkey", result.getAlias());

        } finally {
            removeWorker(workerId);
            removeWorker(tokenId);
        }
    }

    /**
     * Test generating a key in a token, signing and then removing the key and
     * failing signing an additional time.
     */
    @Test
    public void testSigningAndRemovingKey() throws Exception {
        LOG.info("testSigning");
        final int workerId = WORKER_CMS;
        final int tokenId = CRYPTO_TOKEN;

        try {
            setCMSSignerPropertiesSeparateToken();
            workerSession.reloadConfiguration(tokenId);
            workerSession.reloadConfiguration(workerId);
            workerSession.generateSignerKey(new WorkerIdentifier(tokenId), "RSA", "1024", SIGN_KEY_ALIAS, pin.toCharArray());
            workerSession.reloadConfiguration(tokenId);

            cmsSigner(workerId);

            workerSession.removeKey(new WorkerIdentifier(tokenId), SIGN_KEY_ALIAS);

            try {
                cmsSigner(workerId);
                fail("Should get a CryptoTokenOfflineException trying to sign with key removed");
            } catch (CryptoTokenOfflineException e) {
                // expected
            } catch (Exception e) {
                fail("Unexpected exception: " +
                        e.getClass() + ": " + e.getMessage());
            }
            workerSession.reloadConfiguration(tokenId);

            try {
                cmsSigner(workerId, false);
            } catch (CryptoTokenOfflineException expected) { //NOPMD
                // expected
            } catch (Exception e) {
                fail("Unexpected exception: " + e.getClass().getName() + ": " + e.getMessage());
            }


        } finally {
            removeWorker(workerId);
            removeWorker(tokenId);
        }
    }
}
