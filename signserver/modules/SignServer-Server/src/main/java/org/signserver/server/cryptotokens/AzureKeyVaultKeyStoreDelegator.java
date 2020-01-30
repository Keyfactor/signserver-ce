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

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import org.cesecore.keys.token.AzureCryptoToken;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.server.IServices;

/**
 * Implementation of KeyStoreDelegator using an Azure Key Vault cloud
 * key vault implementation from CESeCore.
 *
 * @author Markus Kilås
 * @version $Id$
 */
class AzureKeyVaultKeyStoreDelegator implements KeyStoreDelegator {
    
    private final AzureCryptoToken delegate;

    public AzureKeyVaultKeyStoreDelegator(AzureCryptoToken delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean containsAlias(String alias) throws KeyStoreException {
        return delegate.isAliasUsed(alias);
    }

    @Override
    public void deleteEntry(String alias) throws KeyStoreException {
        try {
            delegate.deleteEntry(alias);
        } catch (NoSuchAlgorithmException | CertificateException | IOException |
                 org.cesecore.keys.token.CryptoTokenOfflineException ex) {
            throw new KeyStoreException("Failed to delete entry", ex);
        }
    }

    @Override
    public PublicKey getPublicKey(String keyAlias) throws KeyStoreException {
        try {
            return delegate.getPublicKey(keyAlias);
        } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
            throw new KeyStoreException(ex);
        }
    }

    @Override
    public PrivateKey aquirePrivateKey(String alias, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CryptoTokenOfflineException {
        try {
            return delegate.getPrivateKey(alias);
        } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
    }

    @Override
    public void releasePrivateKey(PrivateKey privateKey) {
    }

    @Override
    public List<TokenEntry> getEntries() throws KeyStoreException, CryptoTokenOfflineException {
        try {
            final ArrayList<TokenEntry> tokenEntries = new ArrayList<>();
            for (String alias : delegate.getAliases()) {
                TokenEntry entry = new TokenEntry(alias, TokenEntry.TYPE_PRIVATEKEY_ENTRY);
                tokenEntries.add(entry);
            }
            return tokenEntries;
        } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
    }

    @Override
    public void addAdditionalDataToEntry(TokenEntry entry, char[] authCode, IServices services) throws KeyStoreException, CryptoTokenOfflineException {
        System.err.println("TODO: Add aditional data to entry");
        try {
            entry.setParsedChain(new Certificate[0]);
            //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        } catch (CertificateEncodingException ex) {
            java.util.logging.Logger.getLogger(AzureKeyVaultCryptoToken.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void setKeyEntry(String alias, PrivateKey key, char[] authCode, Certificate[] certificate) throws KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
