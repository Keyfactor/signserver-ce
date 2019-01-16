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
package org.signserver.peers.ejb.keybind;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.util.CertTools;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.OperationUnsupportedException;
import org.signserver.common.QueryException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import org.signserver.server.cryptotokens.TokenEntry;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.server.log.AdminInfo;

/**
 * Crypto token management operations needed by peers.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Stateless
public class CryptoTokenManagementSessionBean implements CryptoTokenManagementSessionLocal {

    @EJB
    private WorkerSessionLocal workerSession;

    @Override
    public CryptoToken getCryptoToken(int cryptoTokenId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public CryptoTokenInfo getCryptoTokenInfo(int cryptoTokenId) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean isCryptoTokenStatusActive(int cryptoTokenId) {
        try {
            return workerSession.isTokenActive(new WorkerIdentifier(cryptoTokenId));
        } catch (InvalidWorkerIdException ex) {
            return false;
        }
    }

    @Override
    public List<Integer> getCryptoTokenIds(AuthenticationToken authenticationToken) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void activate(AuthenticationToken authenticationToken, int cryptoTokenId, char[] authenticationCode) throws AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void deactivate(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void deleteCryptoToken(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean isCryptoTokenStatusActive(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException {
        return isCryptoTokenStatusActive(cryptoTokenId);
    }

    @Override
    public void createCryptoToken(AuthenticationToken authenticationToken, String tokenName, Integer cryptoTokenId, String className, Properties properties, byte[] data, char[] authenticationCode) throws AuthorizationDeniedException, CryptoTokenNameInUseException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, NoSuchSlotException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int createCryptoToken(AuthenticationToken authenticationToken, String tokenName, String className, Properties properties, byte[] data, char[] authenticationCode) throws AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, NoSuchSlotException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void saveCryptoToken(AuthenticationToken authenticationToken, int cryptoTokenId, String tokenName, Properties properties, char[] authenticationCode) throws AuthorizationDeniedException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, NoSuchSlotException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void saveCryptoToken(AuthenticationToken authenticationToken, int cryptoTokenId, String newName, String newPlaceholders) throws AuthorizationDeniedException, CryptoTokenNameInUseException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public CryptoTokenInfo getCryptoTokenInfo(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<CryptoTokenInfo> getCryptoTokenInfos(AuthenticationToken authenticationToken) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Integer getIdFromName(String cryptoTokenName) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<String> getKeyPairAliases(AuthenticationToken authenticationToken, int cryptoTokenId) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void createKeyPair(AuthenticationToken authenticationToken, int cryptoTokenId, String alias, String keySpecification) throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void createKeyPairWithSameKeySpec(AuthenticationToken authenticationToken, int cryptoTokenId, String currentSignKeyAlias, String nextSignKeyAlias) throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void createKeyPairFromTemplate(AuthenticationToken authenticationToken, int cryptoTokenId, String alias, String keySpecification) throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void testKeyPair(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void removeKeyPair(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws AuthorizationDeniedException, CryptoTokenOfflineException, InvalidKeyException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void removeKeyPairPlaceholder(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws AuthorizationDeniedException, InvalidKeyException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<KeyPairInfo> getKeyPairInfos(AuthenticationToken admin, int cryptoTokenId) throws CryptoTokenOfflineException, AuthorizationDeniedException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public KeyPairInfo getKeyPairInfo(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws CryptoTokenOfflineException, AuthorizationDeniedException {
        if (alias == null) {
            throw new CryptoTokenOfflineException("No alias");
        }
        try {
            QueryCriteria qc = QueryCriteria.create().add(new Term(RelationalOperator.EQ, CryptoTokenHelper.TokenEntryFields.keyAlias.name(), alias));            
            TokenSearchResults entries = workerSession.searchTokenEntries(new AdminInfo("CLI user", null, null), new WorkerIdentifier(cryptoTokenId), 0, 1, qc, false, Collections.<String, Object>emptyMap());
            if (entries.getEntries().isEmpty()) {
                throw new CryptoTokenOfflineException("Key with alias " + alias + " not available.");
            }
            TokenEntry entry = entries.getEntries().get(0);
            Certificate[] chain = entry.getParsedChain();
            String keyAlgorithm = null;
            String algorithmSpec = null;
            String subjectKeyId = null;
            if (chain != null && chain.length > 0) {
                PublicKey publicKey = entry.getParsedChain()[0].getPublicKey();
                keyAlgorithm = publicKey.getAlgorithm();
                algorithmSpec = AlgorithmTools.getKeySpecification(publicKey);
                subjectKeyId = Hex.toHexString(CertTools.getSubjectKeyId(chain[0]));
            }
            return new KeyPairInfo(alias, keyAlgorithm, algorithmSpec, subjectKeyId);
        } catch (InvalidWorkerIdException | org.signserver.common.CryptoTokenOfflineException | QueryException | InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | OperationUnsupportedException | CertificateException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
    }

    @Override
    public PublicKeyWrapper getPublicKey(AuthenticationToken authenticationToken, int cryptoTokenId, String alias) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean updatePin(AuthenticationToken authenticationToken, Integer cryptoTokenId, char[] currentAuthenticationCode, char[] newAuthenticationCode, boolean updateOnly) throws AuthorizationDeniedException, CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean isAliasUsedInCryptoToken(int cryptoTokenId, String alias) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
