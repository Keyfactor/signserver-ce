/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.server.cryptotokens;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.p11.PKCS11Utils;
import org.cesecore.keys.token.p11.exception.P11RuntimeException;
import org.signserver.server.IServices;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_ALGORITHM;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_MODIFIABLE;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_PKCS11_ATTRIBUTES;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_PUBLIC_EXPONENT;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_SIGNINGS;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_SPECIFICATION;

/**
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class JavaKeyStoreDelegator implements KeyStoreDelegator {
    private static final Logger LOG = Logger.getLogger(JavaKeyStoreDelegator.class);
    
    private final KeyStore keystore;

    public JavaKeyStoreDelegator(final KeyStore keystore) {
        this.keystore = keystore;
    }
    
    @Override
    public boolean containsAlias(String alias) throws KeyStoreException {
        return keystore.containsAlias(alias);
    }

    @Override
    public void deleteEntry(String alias) throws KeyStoreException {
        keystore.deleteEntry(alias);
    }

    @Override
    public Enumeration<String> aliases() throws KeyStoreException {
        return keystore.aliases();
    }

    @Override
    public boolean isKeyEntry(String keyAlias) throws KeyStoreException {
        return keystore.isKeyEntry(keyAlias);
    }

    @Override
    public Certificate getCertificate(String keyAlias) throws KeyStoreException {
        return keystore.getCertificate(keyAlias);
    }

    @Override
    public Key getKey(String alias, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return keystore.getKey(alias, password);
    }

    @Override
    public List<TokenEntry> getEntries(int startIndex, int max)
        throws KeyStoreException {
        final Enumeration<String> e = keystore.aliases();
        final List<TokenEntry> result = new LinkedList<>();
        
        final long maxIndex = (long) startIndex + max;
        for (int i = 0; i < maxIndex && e.hasMoreElements(); i++) {
            final String keyAlias = e.nextElement();

            if (i >= startIndex) {
                final String type;
                if (keystore.entryInstanceOf(keyAlias, KeyStore.PrivateKeyEntry.class)) {
                    type = TokenEntry.TYPE_PRIVATEKEY_ENTRY;
                } else if (keystore.entryInstanceOf(keyAlias, KeyStore.SecretKeyEntry.class)) {
                    type = TokenEntry.TYPE_SECRETKEY_ENTRY;
                } else if (keystore.entryInstanceOf(keyAlias, KeyStore.TrustedCertificateEntry.class)) {
                    type = TokenEntry.TYPE_TRUSTED_ENTRY;
                }  else {
                    type = null;
                }

                TokenEntry entry = new TokenEntry(keyAlias, type);

                result.add(entry);
            }
        }
        
        return result;
    }

    @Override
    public Date getCreationDate(String keyAlias) throws KeyStoreException {
        return keystore.getCreationDate(keyAlias);
    }

    @Override
    public Certificate[] getCertificateChain(String keyAlias) throws KeyStoreException {
        return keystore.getCertificateChain(keyAlias);
    }

    @Override
    public void addAdditionalDataToEntry(final TokenEntry entry,
                                         final char[] authCode,
                                         final IServices services)
            throws KeyStoreException {
        final Map<String, String> info = new HashMap<>();
        final String keyAlias = entry.getAlias();
        final String type = entry.getType();
        
        try {
            Date creationDate = keystore.getCreationDate(keyAlias);
            entry.setCreationDate(creationDate);
        } catch (ProviderException ex) {} // NOPMD: We ignore if it is not supported

        if (TokenEntry.TYPE_PRIVATEKEY_ENTRY.equals(type)) {
            final Certificate[] chain = keystore.getCertificateChain(keyAlias);
            if (chain.length > 0) {
                final PublicKey pubKey = chain[0].getPublicKey();
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
                info.put(INFO_KEY_SIGNINGS, String.valueOf(CryptoTokenHelper.getNoOfSignings(pubKey, services)));
            }
            try {
                entry.setParsedChain(chain);
            } catch (CertificateEncodingException ex) {
                info.put("Error", ex.getMessage());
                LOG.error("Certificate could not be encoded for alias: " + keyAlias, ex);
            }

            if (CryptoTokenHelper.isJREPatched()) {
                final PKCS11Utils p11 = PKCS11Utils.getInstance();

                Key key = null;
                String keyError = null;
                try {
                    key = keystore.getKey(keyAlias, null);
                } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
                    keyError = ex.getMessage();
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Unable to get key to query P11 info", ex);
                    }
                }
                final String providerName = keystore.getProvider().getName();

                // Modifiable
                if (key == null) {
                    info.put(INFO_KEY_MODIFIABLE, "Error: " + keyError);
                } else {
                    final boolean modifiable = p11.isKeyModifiable(key, providerName);
                    info.put(INFO_KEY_MODIFIABLE, String.valueOf(modifiable));
                }

                // Security Info
                if (key != null) {
                    try {
                        final StringBuilder sb = new StringBuilder();
                        p11.securityInfo(key, providerName, sb);
                        info.put(INFO_KEY_PKCS11_ATTRIBUTES, sb.toString().replace("  ", "\n"));
                    } catch (P11RuntimeException ex) {
                        info.put(INFO_KEY_PKCS11_ATTRIBUTES, "Error: " + ex.getMessage());
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Unable to query security info for key", ex);
                        }
                    }
                }

            }
        } else if (TokenEntry.TYPE_TRUSTED_ENTRY.equals(type)) {
            Certificate certificate = keystore.getCertificate(keyAlias);
            try {
                entry.setParsedTrustedCertificate(certificate);
            } catch (CertificateEncodingException ex) {
                info.put("Error", ex.getMessage());
                LOG.error("Certificate could not be encoded for alias: " + keyAlias, ex);
            }
            final Certificate[] chain = new Certificate[0];
            try {
                entry.setParsedChain(chain);
            } catch (CertificateEncodingException ex) {
                LOG.error("Certificate could not be encoded for alias: " + keyAlias, ex);
            }
            info.put(INFO_KEY_SIGNINGS, String.valueOf(CryptoTokenHelper.getNoOfSignings(certificate.getPublicKey(), services)));
            info.put(INFO_KEY_ALGORITHM, "Certificate");
            info.put(INFO_KEY_SPECIFICATION, "n/a"); // Key specification is not applicable for trusted entries 
        } else if (TokenEntry.TYPE_SECRETKEY_ENTRY.equals(type)) {
            try {
                SecretKey secretKey = (SecretKey) keystore.getKey(keyAlias, authCode);

                if (secretKey != null) {
                    String secretKeyAlgo = secretKey.getAlgorithm();
                    if (secretKeyAlgo.equals("1.3.14.3.2.7")) {
                        secretKeyAlgo = "DES";
                    }
                    info.put(INFO_KEY_ALGORITHM, secretKeyAlgo);
                }
                info.put(INFO_KEY_SPECIFICATION, "n/a");
                final Certificate[] chain = new Certificate[0];
                try {
                    entry.setParsedChain(chain);
                } catch (CertificateEncodingException ex) {
                    LOG.error("Certificate could not be encoded for alias: " + keyAlias, ex);
                }
            } catch (NoSuchAlgorithmException | UnrecoverableEntryException ex) {
                info.put("Error", ex.getMessage());
                LOG.error("Unable to get secret key for alias: " + keyAlias, ex);
            }
        }
        entry.setInfo(info);
    }

    @Override
    public void setKeyEntry(String alias, PrivateKey key, char[] authCode,
                            Certificate[] certificate) throws KeyStoreException {
        keystore.setKeyEntry(alias, key, authCode, certificate);
    }
    
}
