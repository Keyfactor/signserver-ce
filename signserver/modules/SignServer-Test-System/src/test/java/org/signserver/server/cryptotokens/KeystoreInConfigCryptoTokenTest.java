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

import java.util.HashSet;
import java.util.Set;
import org.apache.log4j.Logger;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;

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
    private static final String KEYSTORE_NAME = "p12testkeystore1234";

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }
    
    private void setCMSSignerPropertiesSeparateToken(final int workerId, final int tokenId, boolean autoActivate) throws Exception {
        // Setup crypto token
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + tokenId + ".CLASSPATH", "org.signserver.server.signers.CryptoWorker");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + tokenId + ".SIGNERTOKEN.CLASSPATH", KeystoreInConfigCryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", "TestCryptoTokenInConfig");

        if (autoActivate) {
            workerSession.setWorkerProperty(tokenId, "KEYSTOREPASSWORD", pin);
        } else {
            workerSession.removeWorkerProperty(workerId, "KEYSTOREPASSWORD");
        }

        // Setup worker
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".CLASSPATH", "org.signserver.module.cmssigner.CMSSigner");
        workerSession.setWorkerProperty(workerId, "NAME", "CMSSignerConfigToken");
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, "CRYPTOTOKEN", "TestCryptoTokenInConfig");
    }
    
    /**
     * Tests setting up a CMS Signer, giving it a certificate and sign a file
     */
    public void testSigning() throws Exception {
        LOG.info("testSigning");
        final int workerId = WORKER_CMS;
        final int tokenId = CRYPTO_TOKEN;

        try {
            setCMSSignerPropertiesSeparateToken(workerId, tokenId, true);
            workerSession.reloadConfiguration(workerId);
            workerSession.reloadConfiguration(tokenId);
            workerSession.generateSignerKey(tokenId, "RSA", "1024", SIGN_KEY_ALIAS, pin.toCharArray());
            workerSession.reloadConfiguration(tokenId);

            cmsSigner(workerId);
        } finally {
            removeWorker(workerId);
            removeWorker(tokenId);
        }
    }
    
    /**
     * Test generating an additional key.
     * 
     * @throws Exception 
     */
    public void testGenerateKey() throws Exception {
        LOG.info("testGenerateKey");
        
        final int workerId = WORKER_CMS;
        final int tokenId = CRYPTO_TOKEN;
        
        try {
            setCMSSignerPropertiesSeparateToken(workerId, tokenId, true);
            workerSession.reloadConfiguration(workerId);
            workerSession.reloadConfiguration(tokenId);

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
            
        } finally {
            removeWorker(workerId);
            removeWorker(tokenId);
        }
    }
    
    /**
     * Test removing a key.
     * 
     * @throws Exception 
     */
    public void testRemoveKey() throws Exception {
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
            removeWorker(workerId);
            removeWorker(tokenId);
        }
    }
}
