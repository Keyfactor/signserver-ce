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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
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
import org.signserver.common.WorkerType;
import org.signserver.ejb.interfaces.WorkerSessionRemote;

import static org.junit.Assert.assertEquals;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.SECRET_KEY_PREFIX;

/**
 * Generic CryptoToken tests using PKCS#11.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class P11CryptoTokenTest extends CryptoTokenTestBase {

    private static final String CRYPTO_TOKEN_NAME = "TestCryptoTokenP11";
    private static final int CRYPTO_TOKEN = 30100;

    private final String sharedLibraryName;
    private final String slot;
    private final String pin;
    private final String existingKey1;
    private final String testSecretKeyAlias = "testSecretKey";

    private final WorkerSessionRemote workerSession = testCase.getWorkerSession();

    public P11CryptoTokenTest() {
        sharedLibraryName = testCase.getConfig().getProperty("test.p11.sharedLibraryName");
        slot = testCase.getConfig().getProperty("test.p11.slot");
        pin = testCase.getConfig().getProperty("test.p11.pin");
        existingKey1 = testCase.getConfig().getProperty("test.p11.existingkey1");
    }

    @Before
    public void setUp() {
        Assume.assumeFalse("P11NG".equalsIgnoreCase(testCase.getConfig().getProperty("test.p11.provider")));
        SignServerUtil.installBCProvider();
    }

    private void setupCryptoTokenProperties() {
        // Setup token
        workerSession.setWorkerProperty(CRYPTO_TOKEN, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(CRYPTO_TOKEN, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
        workerSession.setWorkerProperty(CRYPTO_TOKEN, WorkerConfig.TYPE, WorkerType.CRYPTO_WORKER.name());
        workerSession.setWorkerProperty(CRYPTO_TOKEN, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(CRYPTO_TOKEN, "SHAREDLIBRARYNAME", sharedLibraryName);
        workerSession.setWorkerProperty(CRYPTO_TOKEN, "SLOT", slot);
        workerSession.setWorkerProperty(CRYPTO_TOKEN, "PIN", pin);
        workerSession.setWorkerProperty(CRYPTO_TOKEN, "DEFAULTKEY", existingKey1); // Test key
        workerSession.setWorkerProperty(CRYPTO_TOKEN, "ATTRIBUTES",
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
    public void testDisabled() throws Exception {
        try {
            setupCryptoTokenProperties();
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
    public void testSearchTokenEntries_PKCS11CryptoToken() throws Exception {
        try {
            setupCryptoTokenProperties();
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            searchTokenEntriesHelper(existingKey1);
        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }

    @Test
    public void testImportCertificateChain_PKCS11CryptoToken() throws Exception {
        try {
            setupCryptoTokenProperties();
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            importCertificateChainHelper(existingKey1);
        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }

    @Test
    public void testExportCertificateChain_PKCS11CryptoToken() throws Exception {
        try {
            setupCryptoTokenProperties();
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            exportCertificatesHelper(existingKey1);
        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }

    private void secretKeyGenerationHelper(String algo, String keySpec) throws Exception {
        try {
            setupCryptoTokenProperties();
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            removeExisting(testSecretKeyAlias);
            generateKey(algo, keySpec, testSecretKeyAlias);
            findNewEntry(testSecretKeyAlias);
        } finally {
            removeKey(testSecretKeyAlias);
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }

    /**
     * Tests AES secret key generation.
     */
    @Test
    public void testGenerateSecretKey_AES_256_PKCS11CryptoToken() throws Exception {
        secretKeyGenerationHelper("AES", "256");
    }

    /**
     * Tests DES secret key generation.
     */
    @Test
    public void testGenerateSecretKey_DES_56_PKCS11CryptoToken() throws Exception {
        secretKeyGenerationHelper("DES", "56");
    }

    /**
     * Tests DESede secret key generation.
     */
    @Test
    public void testGenerateSecretKey_DESede_168_PKCS11CryptoToken() throws Exception {
        secretKeyGenerationHelper(SECRET_KEY_PREFIX + "DESede", "168");
    }

    /**
     * Test key removal method.
     *
     * @throws Exception in case of error
     */
    @Test
    public void testRemoveKey_PKCS11CryptoToken() throws Exception {
        try {
            setupCryptoTokenProperties();
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            removeKeyHelper();
        } finally {
            testCase.removeWorker(CRYPTO_TOKEN);
        }
    }

    private void removeExisting(String alias) throws CryptoTokenOfflineException, OperationUnsupportedException, QueryException, AuthorizationDeniedException, InvalidWorkerIdException, InvalidAlgorithmParameterException, SignServerException, KeyStoreException, UnsupportedCryptoTokenParameter {
        TokenSearchResults searchResults = searchTokenEntries(0, 1, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), alias)), true);
        List<TokenEntry> entries = searchResults.getEntries();
        if (!entries.isEmpty()) {
            removeKey(alias);
        }
    }

    private void findNewEntry(String alias) throws CryptoTokenOfflineException, OperationUnsupportedException, QueryException, AuthorizationDeniedException, InvalidWorkerIdException, InvalidAlgorithmParameterException, SignServerException, KeyStoreException, UnsupportedCryptoTokenParameter {
        TokenSearchResults searchResults = searchTokenEntries(0, 1, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), alias)), true);
        List<TokenEntry> entries = searchResults.getEntries();
        assertEquals(1, entries.size());
    }

    @Override
    public TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData) throws OperationUnsupportedException, CryptoTokenOfflineException, QueryException, InvalidWorkerIdException, AuthorizationDeniedException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        return testCase.getWorkerSession().searchTokenEntries(new WorkerIdentifier(CRYPTO_TOKEN), startIndex, max, qc, includeData, Collections.emptyMap());
    }

    @Override
    public void generateKey(String keyType, String keySpec, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        testCase.getWorkerSession().generateSignerKey(new WorkerIdentifier(CRYPTO_TOKEN), keyType, keySpec, alias, null);
    }

    @Override
    public boolean removeKey(String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException, KeyStoreException {
        return testCase.getWorkerSession().removeKey(new WorkerIdentifier(CRYPTO_TOKEN), alias);
    }

    @Override
    protected void importCertificateChain(List<Certificate> chain, String alias)
            throws CryptoTokenOfflineException, IllegalArgumentException,
            CertificateException, OperationUnsupportedException {
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
