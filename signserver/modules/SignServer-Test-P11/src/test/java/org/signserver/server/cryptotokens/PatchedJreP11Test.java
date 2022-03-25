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
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
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
    private static final Logger LOG = Logger.getLogger(PatchedJreP11Test.class);
    
    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenP11";
    private static final int CRYPTO_TOKEN = 30100;
    
    private final CryptoTokenTestBase base = new CryptoTokenTestBase() {
        @Override
        public TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData) throws OperationUnsupportedException, CryptoTokenOfflineException, QueryException, InvalidWorkerIdException, SignServerException, AuthorizationDeniedException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
            return testCase.getWorkerSession().searchTokenEntries(new WorkerIdentifier(CRYPTO_TOKEN), startIndex, max, qc, includeData, Collections.<String, Object>emptyMap());
        }

        @Override
        public void generateKey(String keyType, String keySpec, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException {
            testCase.getWorkerSession().generateSignerKey(new WorkerIdentifier(CRYPTO_TOKEN), keyType, keySpec, alias, null);
        }

        @Override
        public boolean removeKey(String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException, KeyStoreException {
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
        Assume.assumeFalse("P11NG".equalsIgnoreCase(base.getConfig().getProperty("test.p11.provider")));
        SignServerUtil.installBCProvider();
    }
     
    private void setupCryptoTokenProperties(final int tokenId, final String signatureAlgorithm) throws Exception {
        // Setup token
        final Map<String, String> properties = new HashMap<>();

        properties.put(WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        properties.put(WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        properties.put("NAME", CRYPTO_TOKEN_NAME);
        properties.put("SHAREDLIBRARYNAME", sharedLibraryName);
        properties.put("SLOTLABELTYPE", "SLOT_NUMBER");
        properties.put("SLOTLABELVALUE", slot);
        properties.put("PIN", pin);
        properties.put("DEFAULTKEY", existingKey1); // Test key
        properties.put("SIGNATUREALGORITHM", signatureAlgorithm);
        properties.put("ATTRIBUTE.PRIVATE.RSA.CKA_ALLOWED_MECHANISMS", "CKM_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS");
        properties.put("ATTRIBUTES",
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

        workerSession.updateWorkerProperties(tokenId, properties,
                                             Collections.emptyList());
    }

    @Test
    public void testGenerateUnmodifiableKey() throws Exception {
        Assume.assumeTrue("Test requires patched JRE", CryptoTokenHelper.isJREPatched());
        Assume.assumeTrue("Test requires HSM that supports making a key unmodifiable", "true".equalsIgnoreCase(base.getConfig().getProperty("test.p11.MAKE_UNMODIFIABLE_SUPPORTED")));
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
            setupCryptoTokenProperties(CRYPTO_TOKEN, "SHA256withRSA");
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            
            // Remove old key (if one)
            TokenSearchResults searchResults = base.searchTokenEntries(0, 1, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), testKeyName)), true);
            List<TokenEntry> entries = searchResults.getEntries();
            if (!entries.isEmpty()) {
                base.removeKey(testKeyName);
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
                base.removeKey(testKeyName);
            } catch (Exception ex) { // test should not throw error when key can not be removed although failure  is OK.
                LOG.error("Error in removing key with alias: " + testKeyName + " " + ex.getMessage());
            }

            base.removeWorker(CRYPTO_TOKEN);
        }
    }
    
    /**
     * Tests that if the JRE is patched we have access to the PKCS#11 attributes that the patch is supposed to give us.
     *
     * @throws Exception 
     */
    @Test
    public void testGetTokenEntries() throws Exception {
        Assume.assumeTrue("Test requires patched JRE", CryptoTokenHelper.isJREPatched());
        LOG.info(">testGetTokenEntries");
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, "SHA256withRSA");
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            // Remove old key (if one)
            TokenSearchResults searchResults = base.searchTokenEntries(0, 1, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), existingKey1)), true);
            List<TokenEntry> entries = searchResults.getEntries();
            if (entries.isEmpty()) {
                throw new Exception("Unable to find existing key: " + existingKey1);
            }

            TokenEntry entry = entries.get(0);

            // Should contain attributes
            String infoAttributes = entry.getInfo().get(CryptoTokenHelper.INFO_KEY_PKCS11_ATTRIBUTES);
            assertTrue("attributes: " + infoAttributes, infoAttributes != null && !infoAttributes.isEmpty());

            // Should contain modifiable flag
            String infoModifiable = entry.getInfo().get(CryptoTokenHelper.INFO_KEY_MODIFIABLE);
            assertTrue("modifieable: " + infoModifiable, "true".equalsIgnoreCase(infoModifiable) || "false".equalsIgnoreCase(infoModifiable));            
        } finally {
            base.removeWorker(CRYPTO_TOKEN);
        }
    }
    
    /**
     * Test signing by SunPKCS11 with SHA256withRSAandMGF1 signature algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void testSign_SHA256withRSAandMGF1_SunPKCS11() throws Exception {
        signTestWithPSSAlgorithm("SHA256withRSAandMGF1");
    }

    /**
     * Test signing by SunPKCS11 with SHA256withRSAandMGF1 signature algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void testSign_SHA384withRSAandMGF1_SunPKCS11() throws Exception {
        signTestWithPSSAlgorithm("SHA384withRSAandMGF1");
    }

    /**
     * Test signing by SunPKCS11 with SHA256withRSAandMGF1 signature algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void testSign_SHA512withRSAandMGF1_SunPKCS11() throws Exception {
        signTestWithPSSAlgorithm("SHA512withRSAandMGF1");
    }
    
    private void signTestWithPSSAlgorithm(String algorithm) throws Exception {
        Assume.assumeTrue("Test requires HSM that supports RSASSA-PSS", "true".equalsIgnoreCase(base.getConfig().getProperty("test.p11.PSS_SIGNATURE_ALGORITHM_SUPPORTED")));
        LOG.info("signTestWithPSSAlgorithm: " + algorithm);
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN, algorithm);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            Collection<KeyTestResult> results = workerSession.testKey(new WorkerIdentifier(CRYPTO_TOKEN), existingKey1, pin.toCharArray());
            assertEquals("Results size: " + results, 1, results.size());
            for (KeyTestResult result : results) {
                assertTrue("Success for " + result, result.isSuccess());
            }
        } finally {
            base.removeWorker(CRYPTO_TOKEN);
        }
    }

}
