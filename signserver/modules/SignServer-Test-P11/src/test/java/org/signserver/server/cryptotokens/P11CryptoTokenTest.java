
package org.signserver.server.cryptotokens;/*************************************************************************
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

import java.security.KeyStoreException;
import org.apache.log4j.Logger;
import org.cesecore.util.query.QueryCriteria;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;

/**
 * Generic CryptoToken tests using PKCS#11.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class P11CryptoTokenTest extends CryptoTokenTestBase {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(P11CryptoTokenTest.class);
    
    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenP11";
    private static final int CRYPTO_TOKEN = 30100;
    
    private final String sharedLibraryName;
    private final String sharedLibraryPath;
    private final String slot;
    private final String pin;
    private final String existingKey1;
    
    private final IWorkerSession workerSession = getWorkerSession();
    private final IGlobalConfigurationSession globalSession = getGlobalSession();
    
    public P11CryptoTokenTest() {
        sharedLibraryName = getConfig().getProperty("test.p11.sharedLibraryName");
        sharedLibraryPath = getConfig().getProperty("test.p11.sharedLibraryPath");
        slot = getConfig().getProperty("test.p11.slot");
        pin = getConfig().getProperty("test.p11.pin");
        existingKey1 = getConfig().getProperty("test.p11.existingkey1");
    }
    
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
    }
    
    private void setupCryptoTokenProperties(final int tokenId) throws Exception {
        // Setup token
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + tokenId + ".CLASSPATH", "org.signserver.server.signers.CryptoWorker");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + tokenId + ".SIGNERTOKEN.CLASSPATH", PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(tokenId, "SLOT", slot);
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1); // Test key
        workerSession.setWorkerProperty(tokenId, "ATTRIBUTES",
            "attributes(generate,CKO_PUBLIC_KEY,*) = {\n" +
            "   CKA_TOKEN = false\n" +
            "   CKA_ENCRYPT = true\n" +
            "   CKA_VERIFY = true\n" +
            "   CKA_WRAP = true\n" +
            "}\n" +
            "attributes(generate, CKO_PRIVATE_KEY,*) = {\n" +
            "   CKA_TOKEN = true\n" +
            "   CKA_PRIVATE = true\n" +
            "   CKA_SENSITIVE = true\n" +
            "   CKA_EXTRACTABLE = false\n" +
            "   CKA_DECRYPT = true\n" +
            "   CKA_SIGN = true\n" +
            "   CKA_UNWRAP = true\n" +
            "}");
    }
    
    @Test
    public void testSearchTokenEntries_PKCS11CryptoToken() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            searchTokenEntriesHelper(existingKey1);
        } finally {
            removeWorker(CRYPTO_TOKEN);
        }
    }

    @Override
    protected TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria criteria) throws CryptoTokenOfflineException, KeyStoreException, InvalidWorkerIdException, SignServerException {
        return getWorkerSession().searchTokenEntries(CRYPTO_TOKEN, startIndex, max, criteria);
    }

    @Override
    protected void generateKey(String keyType, String keySpec, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException {
        getWorkerSession().generateSignerKey(CRYPTO_TOKEN, keySpec, keySpec, alias, null);
    }

    @Override
    protected boolean destroyKey(String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException, KeyStoreException {
        return getWorkerSession().removeKey(CRYPTO_TOKEN, alias);
    }
    
    
}
