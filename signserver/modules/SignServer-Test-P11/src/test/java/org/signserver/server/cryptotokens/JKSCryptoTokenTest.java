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
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;
import static junit.framework.TestCase.assertEquals;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.SignServerException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.ejb.interfaces.WorkerSessionRemote;

/**
 * JKS CryptoToken test uses JKS file on file system.
 * 
 * @author Vinay Singh
 * @version $Id$
 */
public class JKSCryptoTokenTest extends CryptoTokenTestBase {

    /**
     * Logger for this class
     */
    private static final Logger LOG = Logger.getLogger(JKSCryptoTokenTest.class);
    
    private final WorkerSessionRemote workerSession = getWorkerSession();    
    private static final int CRYPTO_TOKEN = 10300;
    private static final String CRYPTO_TOKEN_NAME = "TestJKSCryptoToken";
    private final String testSecretKeyAlias="testsecretkey";

    public JKSCryptoTokenTest() {
    }
    
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();        
    }

    private void setupCryptoTokenProperties(final int tokenId) throws Exception {
        final File keystore = new File(getSignServerHome(), "res/test/samplejkskeystore.jks");
        
        // Setup token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(tokenId, "IMPLEMENTATION_CLASS", "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, "CRYPTOTOKEN_IMPLEMENTATION_CLASS", KeystoreCryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(tokenId, "KEYSTOREPATH", keystore.getAbsolutePath());
        workerSession.setWorkerProperty(tokenId, "KEYSTORETYPE", "JKS");
        workerSession.setWorkerProperty(tokenId, "KEYSTOREPASSWORD", "foo123");
    }    
        
    @Test
    public void testGenerateSecretKey_AES_256() throws Exception {
        LOG.info("testGenerateSecretKey_AES_256");
        secretKeyGenerationHelper("AES", "256");
    }
    
    @Test
    public void testGenerateSecretKey_DES_56() throws Exception {
        LOG.info("testGenerateSecretKey_DES_56");
        secretKeyGenerationHelper("DES", "56");
    }
    
    private void secretKeyGenerationHelper(String algo, String keySpec) throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            removeExistingOrFindNewEntry(testSecretKeyAlias, true);
            generateKey(algo, keySpec, testSecretKeyAlias);
            removeExistingOrFindNewEntry(testSecretKeyAlias, false);
        } finally {
            destroyKey(testSecretKeyAlias);
            removeWorker(CRYPTO_TOKEN);
        }
    }
    
    private void removeExistingOrFindNewEntry(String alias, boolean removeExisting) throws CryptoTokenOfflineException, OperationUnsupportedException, QueryException, AuthorizationDeniedException, InvalidWorkerIdException, InvalidAlgorithmParameterException, SignServerException, KeyStoreException, UnsupportedCryptoTokenParameter {
        TokenSearchResults searchResults = searchTokenEntries(0, 1, QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.alias.name(), alias)), true);
        List<TokenEntry> entries = searchResults.getEntries();
        if (removeExisting) {
            if (!entries.isEmpty()) {
                destroyKey(alias);
            }
        } else {
            assertEquals(1, entries.size());
        }
    }

    @Override
    protected TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData) throws InvalidWorkerIdException, AuthorizationDeniedException, SignServerException, OperationUnsupportedException, CryptoTokenOfflineException, QueryException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        return workerSession.searchTokenEntries(new WorkerIdentifier(CRYPTO_TOKEN), startIndex, max, qc, includeData, Collections.<String, Object>emptyMap());
    }

    @Override
    protected void generateKey(String keyType, String keySpec, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException {
        workerSession.generateSignerKey(new WorkerIdentifier(CRYPTO_TOKEN), keyType, keySpec, alias, null);
    }

    @Override
    protected boolean destroyKey(String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException, KeyStoreException {
        return workerSession.removeKey(new WorkerIdentifier(CRYPTO_TOKEN), alias);
    }

    @Override
    protected void importCertificateChain(List<Certificate> chain, String alias) throws CryptoTokenOfflineException, IllegalArgumentException, CertificateException, CertificateEncodingException, OperationUnsupportedException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected ICertReqData genCertificateRequest(ISignerCertReqInfo req, boolean explicitEccParameters, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    protected List<Certificate> getCertificateChain(String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }       
}
