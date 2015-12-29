
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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
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
import org.signserver.ejb.interfaces.WorkerSessionRemote;

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
    private final String slot;
    private final String pin;
    private final String existingKey1;
    
    private final WorkerSessionRemote workerSession = getWorkerSession();
    
    public P11CryptoTokenTest() {
        sharedLibraryName = getConfig().getProperty("test.p11.sharedLibraryName");
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
        workerSession.setWorkerProperty(tokenId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, PKCS11CryptoToken.class.getName());
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
    
    @Test
    public void testImportCertificateChain_PKCS11CryptoToken() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
        
            importCertificateChainHelper(existingKey1);
        } finally {
            removeWorker(CRYPTO_TOKEN);
        }
    }

    @Test
    public void testExportCertificateChain_PKCS11CryptoToken() throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);
        
            exportCertificatesHelper(existingKey1);
        } finally {
            removeWorker(CRYPTO_TOKEN);
        }
    }

    @Override
    protected TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData) throws OperationUnsupportedException, CryptoTokenOfflineException, QueryException, InvalidWorkerIdException, SignServerException, AuthorizationDeniedException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        return getWorkerSession().searchTokenEntries(new WorkerIdentifier(CRYPTO_TOKEN), startIndex, max, qc, includeData, Collections.<String, Object>emptyMap());
    }

    @Override
    protected void generateKey(String keyType, String keySpec, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException {
        getWorkerSession().generateSignerKey(new WorkerIdentifier(CRYPTO_TOKEN), keySpec, keySpec, alias, null);
    }

    @Override
    protected boolean destroyKey(String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException, KeyStoreException {
        return getWorkerSession().removeKey(new WorkerIdentifier(CRYPTO_TOKEN), alias);
    }

    @Override
    protected void importCertificateChain(List<Certificate> chain, String alias)
            throws CryptoTokenOfflineException, IllegalArgumentException,
            CertificateException, CertificateEncodingException, OperationUnsupportedException {
        getWorkerSession().importCertificateChain(new WorkerIdentifier(CRYPTO_TOKEN), getCertByteArrayList(chain), alias, null);
    }
    
    private List<byte[]> getCertByteArrayList(final List<Certificate> chain) throws CertificateEncodingException {
        final List<byte[]> result = new LinkedList<byte[]>();
        
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
        return getWorkerSession().getCertificateRequest(new WorkerIdentifier(CRYPTO_TOKEN), req, explicitEccParameters, alias);
    }

    @Override
    protected List<Certificate> getCertificateChain(String alias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException {
        return getWorkerSession().getSignerCertificateChain(new WorkerIdentifier(CRYPTO_TOKEN), alias);
    }
}
