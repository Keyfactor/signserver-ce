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
package org.signserver.p11ng.common;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
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
import org.signserver.common.WorkerType;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.p11ng.common.cryptotoken.JackNJI11CryptoToken;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.SECRET_KEY_PREFIX;
import org.signserver.server.cryptotokens.CryptoTokenTestBase;
import org.signserver.server.cryptotokens.TokenEntry;
import org.signserver.server.cryptotokens.TokenSearchResults;

/**
 * Generic CryptoToken tests using PKCS#11 & JackNJI11CryptoToken.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@RunWith(Parameterized.class)
public class P11NGCryptoTokenTest extends CryptoTokenTestBase {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(P11NGCryptoTokenTest.class);
    
    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenP11NG";
    private static final int CRYPTO_TOKEN = 32100;
    
    private final String sharedLibraryName;
    private final String slot;
    private final String slotIndex;
    private final Pkcs11SlotLabelType slotLabelType;
    private final String pin;
    private final String existingKey1;
    private final String testSecretKeyAlias = "testSecretKey";
    private final String testPrivateKeyAlias = "testPrivateKey";
    
    private final WorkerSessionRemote workerSession = testCase.getWorkerSession();
    
    public P11NGCryptoTokenTest(final Pkcs11SlotLabelType slotLabelType,
                                final String title) {
        sharedLibraryName = testCase.getConfig().getProperty("test.p11.sharedLibraryName");
        slot = testCase.getConfig().getProperty("test.p11.slot");
        slotIndex = testCase.getConfig().getProperty("test.p11.slotindex");
        this.slotLabelType = slotLabelType;
        pin = testCase.getConfig().getProperty("test.p11.pin");
        existingKey1 = testCase.getConfig().getProperty("test.p11.existingkey1");
    }
    
    @Before
    public void setUp() throws Exception {
        Assume.assumeTrue("P11NG".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.provider")));
        SignServerUtil.installBCProvider();
    }
    
    @Parameters(name = "{1}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[] { Pkcs11SlotLabelType.SLOT_NUMBER,
                                            Pkcs11SlotLabelType.SLOT_NUMBER.name() },
                             new Object[] { Pkcs11SlotLabelType.SLOT_INDEX,
                                            Pkcs11SlotLabelType.SLOT_INDEX.name() });
    }
    
    private void setupCryptoTokenProperties(final int tokenId) throws Exception {
        // Setup token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, JackNJI11CryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "SHAREDLIBRARYNAME", sharedLibraryName);
        
        switch (slotLabelType) {
            case SLOT_NUMBER:
                workerSession.setWorkerProperty(tokenId, "SLOTLABELTYPE", "SLOT_NUMBER");
                workerSession.setWorkerProperty(tokenId, "SLOTLABELVALUE", slot);
                break;
            case SLOT_INDEX:
                workerSession.setWorkerProperty(tokenId, "SLOTLABELTYPE", "SLOT_INDEX");
                workerSession.setWorkerProperty(tokenId, "SLOTLABELVALUE", slotIndex);
                break;
            default:
                throw new IllegalArgumentException("Unsupported slot label type: " + slotLabelType.name());
        }
        workerSession.setWorkerProperty(tokenId, "PIN", pin);
        workerSession.setWorkerProperty(tokenId, "DEFAULTKEY", existingKey1); // Test key
        workerSession.setWorkerProperty(tokenId, "ATTRIBUTE.PUBLIC.RSA.CKA_ENCRYPT", "false");
        workerSession.setWorkerProperty(tokenId, "ATTRIBUTE.PUBLIC.RSA.CKA_VERIFY", "false");
        workerSession.setWorkerProperty(tokenId, "ATTRIBUTE.PUBLIC.RSA.CKA_WRAP", "false");
        workerSession.setWorkerProperty(tokenId, "ATTRIBUTE.PRIVATE.RSA.CKA_SIGN", "true");
        workerSession.setWorkerProperty(tokenId, "ATTRIBUTE.PRIVATE.RSA.CKA_PRIVATE", "true");
        workerSession.setWorkerProperty(tokenId, "ATTRIBUTE.PRIVATE.RSA.CKA_SENSITIVE", "true");
        workerSession.setWorkerProperty(tokenId, "ATTRIBUTE.PRIVATE.RSA.CKA_EXTRACTABLE", "false");
        workerSession.setWorkerProperty(tokenId, "ATTRIBUTE.PRIVATE.RSA.CKA_DECRYPT", "false");
        workerSession.setWorkerProperty(tokenId, "ATTRIBUTE.PRIVATE.RSA.CKA_UNWRAP", "false");
    }

    @Test
    public void testDisabled() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            final String marker = "_MARKER-";
            workerSession.setWorkerProperty(CRYPTO_TOKEN, "SHAREDLIBRARYNAME", marker);
            workerSession.setWorkerProperty(CRYPTO_TOKEN, "DISABLED", "tRUe"); // Note: different casings intended
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            
            String errors = workerSession.getStatus(new WorkerIdentifier(CRYPTO_TOKEN)).getFatalErrors().toString();
            assertTrue("errors contains disabled: " + errors, errors.contains("Disabled"));
            assertFalse("errors not including marker: " + errors, errors.contains(marker));
        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }

    @Test
    public void testSearchTokenEntries_JackNJI11CryptoToken() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
        
            searchTokenEntriesHelper(existingKey1);
        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }
    
    @Test
    public void testImportCertificateChain_JackNJI11CryptoToken() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
        
            importCertificateChainHelper(existingKey1);
        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }

    @Test
    public void testExportCertificateChain_JackNJI11CryptoToken() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
        
            exportCertificatesHelper(existingKey1);
        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }
    
    private void secretKeyGenerationHelper(String algo, String keySpec) throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            removeExisting(testSecretKeyAlias);
            generateKey(algo, keySpec, testSecretKeyAlias);
            findNewEntry(testSecretKeyAlias);
        } finally {
            destroyKey(testSecretKeyAlias);
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }

    /**
     * Tests AES secret key generation.
     * 
     * @throws Exception
     */
    @Test
    public void testGenerateSecretKey_AES_256_JackNJI11CryptoToken() throws Exception {
        secretKeyGenerationHelper("AES", "256");
    }

    /**
     * Tests DES secret key generation.
     * 
     * @throws Exception
     */
    @Test
    public void testGenerateSecretKey_DES_56_JackNJI11CryptoToken() throws Exception {
        secretKeyGenerationHelper("DES", "56");
    }
    
    /**
     * Tests CAST128 secret key generation.
     * 
     * @throws Exception
     */
    @Test
    public void testGenerateSecretKey_CAST128_JackNJI11CryptoToken() throws Exception {
        secretKeyGenerationHelper(SECRET_KEY_PREFIX + "CAST128", "128");
    }
    
    /**
     * Tests DESede secret key generation.
     * 
     * @throws Exception
     */
    @Test
    public void testGenerateSecretKey_DESede_168_JackNJI11CryptoToken() throws Exception {
        secretKeyGenerationHelper(SECRET_KEY_PREFIX + "DESede", "168");
    }

    /**
     * Tests key generation with two different values for a PKCS#11 attribute.
     * @throws Exception 
     */
    @Test
    public void testGeneratePrivateKeyWithAttribute() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            
            // Generate with CKA_DERIVE=false
            workerSession.setWorkerProperty(CRYPTO_TOKEN, "ATTRIBUTE.PRIVATE.RSA.CKA_DERIVE", "false");
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            destroyKey(testPrivateKeyAlias);
            generateKey("RSA", "1024", testPrivateKeyAlias);
            
            // Check that it has CKA_DERIVE=false
            TokenSearchResults searchResults = searchTokenEntries(0, 1, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), testPrivateKeyAlias)), true);
            List<TokenEntry> entries = searchResults.getEntries();
            assertEquals("one generate key", 1, entries.size());
            TokenEntry entry = entries.get(0);
            String infoAttributes = entry.getInfo().get(CryptoTokenHelper.INFO_KEY_PKCS11_ATTRIBUTES);
            assertTrue("attributes: " + infoAttributes, infoAttributes.contains("DERIVE=false"));
            
            // Generate with CKA_DERIVE=true
            workerSession.setWorkerProperty(CRYPTO_TOKEN, "ATTRIBUTE.PRIVATE.RSA.CKA_DERIVE", "true");
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            destroyKey(testPrivateKeyAlias);
            generateKey("RSA", "1024", testPrivateKeyAlias);
            
            // Check that it has CKA_DERIVE=true
            searchResults = searchTokenEntries(0, 1, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), testPrivateKeyAlias)), true);
            entries = searchResults.getEntries();
            assertEquals("one generate key", 1, entries.size());
            entry = entries.get(0);
            infoAttributes = entry.getInfo().get(CryptoTokenHelper.INFO_KEY_PKCS11_ATTRIBUTES);
            assertTrue("attributes: " + infoAttributes, infoAttributes.contains("DERIVE=true"));
        } finally {
            destroyKey(testPrivateKeyAlias);
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }

    /**
     * Tests key generation with two different values for the CKA_ALLOWED_MECHANISMS attribute.
     * @throws Exception 
     */
    @Test
    public void testGeneratePrivateKeyWithAllowedMechanismsAttribute() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            
            // Generate with CKA_DERIVE=false
            workerSession.setWorkerProperty(CRYPTO_TOKEN, "ATTRIBUTE.PRIVATE.RSA.CKA_ALLOWED_MECHANISMS", "CKM_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS");
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            destroyKey(testPrivateKeyAlias);
            generateKey("RSA", "1024", testPrivateKeyAlias);
            
            // Check that it has the allowed mechanisms
            TokenSearchResults searchResults = searchTokenEntries(0, 1, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), testPrivateKeyAlias)), true);
            List<TokenEntry> entries = searchResults.getEntries();
            assertEquals("one generate key", 1, entries.size());
            TokenEntry entry = entries.get(0);
            String infoAttributes = entry.getInfo().get(CryptoTokenHelper.INFO_KEY_ALLOWED_MECHANISMS);
            assertTrue("contains CKM_RSA_PKCS_PSS: " + infoAttributes, infoAttributes.contains("CKM_RSA_PKCS_PSS"));
            assertTrue("contains CKM_RSA_PKCS_PSS: " + infoAttributes, infoAttributes.contains("CKM_SHA256_RSA_PKCS_PSS"));
            assertTrue("contains CKM_RSA_PKCS_PSS: " + infoAttributes, infoAttributes.contains("CKM_SHA384_RSA_PKCS_PSS"));

            // Generate with an other value
            workerSession.setWorkerProperty(CRYPTO_TOKEN, "ATTRIBUTE.PRIVATE.RSA.CKA_ALLOWED_MECHANISMS", "CKM_RSA_PKCS_PSS");
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
            destroyKey(testPrivateKeyAlias);
            generateKey("RSA", "1024", testPrivateKeyAlias);
            
            // Check that it has CKA_ALLOWED_MECHANISMS=CKM_RSA_PKCS_PSS
            searchResults = searchTokenEntries(0, 1, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), testPrivateKeyAlias)), true);
            entries = searchResults.getEntries();
            assertEquals("one generate key", 1, entries.size());
            entry = entries.get(0);
            infoAttributes = entry.getInfo().get(CryptoTokenHelper.INFO_KEY_ALLOWED_MECHANISMS);
            assertEquals("one value", "CKM_RSA_PKCS_PSS", infoAttributes);
        } finally {
            destroyKey(testPrivateKeyAlias);
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }

    private void removeExisting(String alias) throws CryptoTokenOfflineException, OperationUnsupportedException, QueryException, AuthorizationDeniedException, InvalidWorkerIdException, InvalidAlgorithmParameterException, SignServerException, KeyStoreException, UnsupportedCryptoTokenParameter {
        TokenSearchResults searchResults = searchTokenEntries(0, 1, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), alias)), true);
        List<TokenEntry> entries = searchResults.getEntries();
        if (!entries.isEmpty()) {
            destroyKey(alias);
        }
    }
    
    private void findNewEntry(String alias) throws CryptoTokenOfflineException, OperationUnsupportedException, QueryException, AuthorizationDeniedException, InvalidWorkerIdException, InvalidAlgorithmParameterException, SignServerException, KeyStoreException, UnsupportedCryptoTokenParameter {
        TokenSearchResults searchResults = searchTokenEntries(0, 1, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), alias)), true);
        List<TokenEntry> entries = searchResults.getEntries();
        assertEquals(1, entries.size());
    }

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
}
