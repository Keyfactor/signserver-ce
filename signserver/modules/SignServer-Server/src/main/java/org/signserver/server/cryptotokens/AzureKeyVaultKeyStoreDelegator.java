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
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.AzureCryptoToken;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.server.IServices;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_ALGORITHM;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_PUBLIC_EXPONENT;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_SIGNINGS;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_SPECIFICATION;

/**
 * Implementation of KeyStoreDelegator using an Azure Key Vault cloud
 * key vault implementation from CESeCore.
 *
 * @author Markus Kilås
 * @version $Id$
 */
class AzureKeyVaultKeyStoreDelegator implements KeyStoreDelegator {
    // Logger for this class
    private static final Logger LOG = Logger.getLogger(AzureKeyVaultKeyStoreDelegator.class);
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
    public void addAdditionalDataToEntry(final TokenEntry entry,
                                         final char[] authCode,
                                         final IServices services)
            throws KeyStoreException, CryptoTokenOfflineException {
        final Map<String, String> info = new HashMap<>();
        final String keyAlias = entry.getAlias();
        
        try {
            if (TokenEntry.TYPE_PRIVATEKEY_ENTRY.equals(entry.getType())) {
                try {
                    final PublicKey pubKey = delegate.getPublicKey(keyAlias);
                    final String keyAlgorithm =
                                AlgorithmTools.getKeyAlgorithm(pubKey);

                    info.put(INFO_KEY_ALGORITHM, keyAlgorithm);
                    info.put(INFO_KEY_SPECIFICATION,
                             AlgorithmTools.getKeySpecification(pubKey));

                    if (AlgorithmConstants.KEYALGORITHM_RSA.equals(keyAlgorithm)) {
                        final RSAPublicKey rsaKey = (RSAPublicKey) pubKey;

                        info.put(INFO_KEY_PUBLIC_EXPONENT,
                                rsaKey.getPublicExponent().toString(10));
                    }
                    info.put(INFO_KEY_SIGNINGS,
                             String.valueOf(CryptoTokenHelper.getNoOfSignings(pubKey,
                                            services)));


                } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
                    info.put("Error", ex.getMessage());
                    LOG.error("Crypto token offline");
                }
            }
            entry.setParsedChain(new Certificate[0]);
        } catch (CertificateEncodingException ex) {
            info.put("Error", ex.getMessage());
            LOG.error("Certificate could not be encoded for alias: " + keyAlias, ex);
        }

        entry.setInfo(info);
    }

    @Override
    public void setKeyEntry(String alias, PrivateKey key, char[] authCode, Certificate[] certificate) throws KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
