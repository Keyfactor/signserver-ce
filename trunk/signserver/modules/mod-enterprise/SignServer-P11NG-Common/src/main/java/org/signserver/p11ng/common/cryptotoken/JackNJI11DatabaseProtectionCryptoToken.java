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
package org.signserver.p11ng.common.cryptotoken;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.log4j.Logger;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.p11ng.common.provider.SlotEntry;

/**
 * CESeCore CryptoToken wrapper using JackNJI11 intended to be used for database protection.
 *
 * This class is needed as the database protection uses CESeCore CryptoTokens. Only functionality needed
 * for the database protection use case are implemented.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class JackNJI11DatabaseProtectionCryptoToken implements CryptoToken {
    
    /** Logger for this class. */
    private final org.apache.log4j.Logger LOG = Logger.getLogger(JackNJI11DatabaseProtectionCryptoToken.class);

    private JackNJI11CryptoToken token;
    private int id;
    private Properties properties;
    private String tokenName;

    @Override
    public void init(Properties properties, byte[] data, int id) throws Exception {
        this.id = id;
        this.properties = properties;
        // As this is not a SignServer CryptoToken but a CESeCore crypto token we can allow it to load the library by file
        final String sharedLibrary = properties.getProperty("sharedLibrary");
        if (sharedLibrary == null) {
            this.token = new JackNJI11CryptoToken();
        } else {
            this.token = new JackNJI11CryptoToken(sharedLibrary);
        }
        token.init(id, properties, null);
    }

    @Override
    public int getId() {
        return id;
    }

    @Override
    public void activate(char[] authenticationcode) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        try {
            token.activate(String.valueOf(authenticationcode), null);
        } catch (CryptoTokenAuthenticationFailureException ex) {
            CryptoTokenAuthenticationFailedException ex2 = new CryptoTokenAuthenticationFailedException();
            ex2.initCause(ex);
            throw ex2;
        } catch (org.signserver.common.CryptoTokenOfflineException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
    }

    @Override
    public void deactivate() {
        try {
            token.deactivate(null);
        } catch (org.signserver.common.CryptoTokenOfflineException ex) {
            LOG.warn("Unable to deactivate: " + ex.getLocalizedMessage(), ex);
        }
    }

    @Override
    public boolean isAliasUsed(String alias) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public PrivateKey getPrivateKey(String alias) throws CryptoTokenOfflineException {
        return token.getSlot().getReleasableSessionPrivateKey(alias);
    }

    @Override
    public PublicKey getPublicKey(String alias) throws CryptoTokenOfflineException {
        final PublicKey result;
        Certificate certificate = token.getSlot().getCertificate(alias);
        if (certificate != null) {
            result = certificate.getPublicKey();
        } else {
            result = null;
            LOG.warn("No public key for alias: " + alias);
            if (LOG.isDebugEnabled()) {
                StringBuilder sb = new StringBuilder();
                sb.append("Existing aliases (up to first 50):\n");
                Enumeration<SlotEntry> aliases = null;
                try {
                    aliases = token.getSlot().aliases();
                } catch (org.signserver.common.CryptoTokenOfflineException ex) {
                    throw new CryptoTokenOfflineException(ex);
                }
                for (int i = 0; aliases.hasMoreElements() && i < 50; i++) {
                    sb.append(aliases.nextElement().getAlias()).append("\n");
                }
                LOG.debug(sb.toString());
            }
        }
        return result;
    }

    @Override
    public Key getKey(String alias) throws CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void deleteEntry(String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void generateKeyPair(String keySpec, String alias) throws InvalidAlgorithmParameterException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void generateKeyPair(AlgorithmParameterSpec spec, String alias) throws InvalidAlgorithmParameterException, CertificateException, IOException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void generateKey(String algorithm, int keysize, String alias) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, CryptoTokenOfflineException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException, CertificateException, IOException, NoSuchPaddingException, IllegalBlockSizeException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getSignProviderName() {
        return token.getSlot().getProvider().getName();
    }

    @Override
    public String getEncProviderName() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void reset() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getTokenName() {
        return tokenName;
    }

    @Override
    public void setTokenName(String tokenName) {
        this.tokenName = tokenName;
    }

    @Override
    public int getTokenStatus() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Properties getProperties() {
        return properties;
    }

    @Override
    public void setProperties(Properties properties) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void storeKey(String alias, Key key, Certificate[] chain, char[] password) throws KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] getTokenData() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void testKeyPair(String alias) throws InvalidKeyException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void testKeyPair(String alias, PublicKey publicKey, PrivateKey privateKey) throws InvalidKeyException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean doPermitExtractablePrivateKey() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public List<String> getAliases() throws KeyStoreException, CryptoTokenOfflineException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public boolean isAutoActivationPinPresent() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
