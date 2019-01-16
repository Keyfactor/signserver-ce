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
import java.io.FileInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import static org.junit.Assert.assertEquals;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSessionRemote;

/**
 * Tests requiring a patched JRE.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PatchedJreP11Test {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(P11CryptoTokenTest.class);
    
    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenP11";
    private static final int CRYPTO_TOKEN = 30100;
    
    private final CryptoTokenTestBase base = new CryptoTokenTestBase() {
        @Override
        protected TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData) throws OperationUnsupportedException, CryptoTokenOfflineException, QueryException, InvalidWorkerIdException, SignServerException, AuthorizationDeniedException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
            return testCase.getWorkerSession().searchTokenEntries(new WorkerIdentifier(CRYPTO_TOKEN), startIndex, max, qc, includeData, Collections.<String, Object>emptyMap());
        }

        @Override
        protected void generateKey(String keyType, String keySpec, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException {
            testCase.getWorkerSession().generateSignerKey(new WorkerIdentifier(CRYPTO_TOKEN), keyType, keySpec, alias, null);
        }

        @Override
        protected boolean destroyKey(String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException, KeyStoreException {
            return testCase.getWorkerSession().removeKey(new WorkerIdentifier(CRYPTO_TOKEN), alias);
        }

        @Override
        protected void importCertificateChain(List<Certificate> chain, String alias)
                throws CryptoTokenOfflineException, IllegalArgumentException,
                CertificateException, CertificateEncodingException, OperationUnsupportedException {
            testCase.getWorkerSession().importCertificateChain(new WorkerIdentifier(CRYPTO_TOKEN), getCertByteArrayList(chain), alias, null);
        }

        private List<byte[]> getCertByteArrayList(final List<Certificate> chain) throws CertificateEncodingException {
            final List<byte[]> result = new LinkedList<>();

            for (final Certificate cert : chain) {
                result.add(cert.getEncoded());
            }

            return result;
        }

        @Override
        protected ICertReqData genCertificateRequest(final ISignerCertReqInfo req,
                                                     final boolean explicitEccParameters,
                                                     final String alias)
                throws CryptoTokenOfflineException, InvalidWorkerIdException {
            return testCase.getWorkerSession().getCertificateRequest(new WorkerIdentifier(CRYPTO_TOKEN), req, explicitEccParameters, alias);
        }

        @Override
        protected List<Certificate> getCertificateChain(String alias)
                throws CryptoTokenOfflineException, InvalidWorkerIdException {
            return testCase.getWorkerSession().getSignerCertificateChain(new WorkerIdentifier(CRYPTO_TOKEN), alias);
        }
    };
    
    private final String sharedLibraryName;
    private final String slot;
    private final String pin;
    private final String existingKey1;
    
    private final WorkerSessionRemote workerSession = base.getWorkerSession();
    
    public PatchedJreP11Test() {
        sharedLibraryName = base.getConfig().getProperty("test.p11.sharedLibraryName");
        slot = base.getConfig().getProperty("test.p11.slot");
        pin = base.getConfig().getProperty("test.p11.pin");
        existingKey1 = base.getConfig().getProperty("test.p11.existingkey1");
    }
    
    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }
    
    private void setupCryptoTokenProperties(final int tokenId) throws Exception {
        // Setup token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(tokenId, "SLOTLABELTYPE", "SLOT_NUMBER");
        workerSession.setWorkerProperty(tokenId, "SLOTLABELVALUE", slot);
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1); // Test key
        workerSession.setWorkerProperty(tokenId, "SIGNATUREALGORITHM", "SHA256withRSAandMGF1");
        workerSession.setWorkerProperty(tokenId, "ATTRIBUTE.PRIVATE.RSA.CKA_ALLOWED_MECHANISMS", "CKM_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS");
        workerSession.setWorkerProperty(tokenId, "ATTRIBUTES",
            "attributes(generate,CKO_PUBLIC_KEY,*) = {\n" +
            "   CKA_TOKEN = false\n" +
            "   CKA_ENCRYPT = false\n" +
            "   CKA_VERIFY = true\n" +
            "   CKA_WRAP = false\n" +
            "}\n" +
            "attributes(generate, CKO_PRIVATE_KEY,*) = {\n" +
            "   CKA_TOKEN = true\n" +
            "   CKA_PRIVATE = true\n" +
            "   CKA_SENSITIVE = true\n" +
            "   CKA_EXTRACTABLE = false\n" +
            "   CKA_DECRYPT = false\n" +
            "   CKA_SIGN = true\n" +
            "   CKA_UNWRAP = false\n" +
            "}");
    }

    @Test
    public void testGenerateUnmodifiableKey() throws Exception {
        Assume.assumeTrue("Test requires patched JRE", CryptoTokenHelper.isJREPatched());
        LOG.info(">testGenerateUnmodifiableKey");
        Properties properties = new Properties();
        try (FileInputStream fin = new FileInputStream(new File(PathUtil.getAppHome(), "conf/cesecore.properties"))) {
            properties.load(fin);
        }
        if (!Boolean.parseBoolean(properties.getProperty("pkcs11.makeKeyUnmodifiableAfterGeneration", "false"))) {
            throw new Exception("Test expects conf/cesecore.properties configured with pkcs11.makeKeyUnmodifiableAfterGeneration=true");
        }
        
        final String testKeyName = "_test_modifable_key";
        
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            
            // Remove old key (if one)
            TokenSearchResults searchResults = base.searchTokenEntries(0, 1, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), testKeyName)), true);
            List<TokenEntry> entries = searchResults.getEntries();
            if (!entries.isEmpty()) {
                base.destroyKey(testKeyName);
            }
            
            // Generate the key
            base.generateKey("RSA", "2048", testKeyName);
            
            // Query one specific entry
            searchResults = base.searchTokenEntries(0, 1, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), testKeyName)), true);
            entries = searchResults.getEntries();
            assertEquals(1, entries.size());
            
            assertEquals("Modifiable field", Boolean.FALSE.toString(), entries.get(0).getInfo().get(CryptoTokenHelper.INFO_KEY_MODIFIABLE));
        } finally {
            try {
                base.destroyKey(testKeyName);
            } catch (Exception ex) { // test should not throw error when key can not be removed although failure  is OK.
                LOG.error("Error in removing key with alias: " + testKeyName + " " + ex.getMessage());
            }

            base.removeWorker(CRYPTO_TOKEN);
        }
    }

}
