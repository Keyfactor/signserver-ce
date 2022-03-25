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
import java.io.FileNotFoundException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;
import static junit.framework.TestCase.assertEquals;
import org.apache.commons.io.FileUtils;
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
import static org.signserver.server.cryptotokens.CryptoTokenHelper.SECRET_KEY_PREFIX;

/**
 * JKS CryptoToken test uses JKS file on file system, The JKS keystore in the file uses a standard PKCS12 format.
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
    private final String testSecretKeyAlias = "testsecretkey";
    private static final String KEYSTORE_NAME = "jkstestkeystore1234";
    private File keystoreFile;
    private final File keystore;
    
    public JKSCryptoTokenTest() throws FileNotFoundException {
        keystore = new File(getSignServerHome(), "res/test/samplejkskeystore.jks");
    }

    private void setupCryptoTokenProperties(final int tokenId) throws Exception {        
        keystoreFile = File.createTempFile(KEYSTORE_NAME, ".jks");
        FileUtils.copyFile(keystore, keystoreFile);
        
        // Setup token
        workerSession.setWorkerProperty(tokenId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(tokenId, "IMPLEMENTATION_CLASS", "org.signserver.server.signers.CryptoWorker");
        workerSession.setWorkerProperty(tokenId, "CRYPTOTOKEN_IMPLEMENTATION_CLASS", KeystoreCryptoToken.class.getName());
        workerSession.setWorkerProperty(tokenId, "NAME", CRYPTO_TOKEN_NAME);
        workerSession.setWorkerProperty(tokenId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(tokenId, "KEYSTOREPATH", keystoreFile.getAbsolutePath());
        workerSession.setWorkerProperty(tokenId, "KEYSTORETYPE", "JKS");
        workerSession.setWorkerProperty(tokenId, "KEYSTOREPASSWORD", "foo123");
    }    
    
    /**
     * Tests AES secret key generation.
     * 
     * @throws Exception
     */    
    @Test
    public void testGenerateSecretKey_AES_256() throws Exception {
        LOG.info("testGenerateSecretKey_AES_256");
        secretKeyGenerationHelper("AES", "256");
    }
    
    /**
     * Tests DES secret key generation.
     * 
     * @throws Exception
     */  
    @Test
    public void testGenerateSecretKey_DES_56() throws Exception {
        LOG.info("testGenerateSecretKey_DES_56");
        secretKeyGenerationHelper("DES", "56");
    }
    
    /**
     * Tests Blowfish secret key generation.
     *
     * @throws Exception
     */
    @Test
    public void testGenerateSecretKey_Blowfish_168_JKSTypeP12CryptoToken() throws Exception {
        LOG.info("testGenerateSecretKey_Blowfish_168_JKSTypeP12CryptoToken");
        secretKeyGenerationHelper(SECRET_KEY_PREFIX + "Blowfish", "168");
    }
    
    private void secretKeyGenerationHelper(String algo, String keySpec) throws Exception {
        try {
            setupCryptoTokenProperties(CRYPTO_TOKEN);
            workerSession.reloadConfiguration(CRYPTO_TOKEN);

            removeExisting(testSecretKeyAlias);
            generateKey(algo, keySpec, testSecretKeyAlias);
            findNewEntry(testSecretKeyAlias);
        } finally {
            removeKey(testSecretKeyAlias);
            removeWorker(CRYPTO_TOKEN);
            FileUtils.deleteQuietly(keystoreFile);
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
    public TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData) throws InvalidWorkerIdException, AuthorizationDeniedException, SignServerException, OperationUnsupportedException, CryptoTokenOfflineException, QueryException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        return workerSession.searchTokenEntries(new WorkerIdentifier(CRYPTO_TOKEN), startIndex, max, qc, includeData, Collections.<String, Object>emptyMap());
    }

    @Override
    public void generateKey(String keyType, String keySpec, String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException {
        workerSession.generateSignerKey(new WorkerIdentifier(CRYPTO_TOKEN), keyType, keySpec, alias, null);
    }

    @Override
    public boolean removeKey(String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, SignServerException, KeyStoreException {
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
