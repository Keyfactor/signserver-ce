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
 * KeyStoreDelegator implementation operating on a Java KeyStore instance,
 * used by keystore (P12 and JKS) and Sun P11 crypto tokens.
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
    public PublicKey getPublicKey(String keyAlias) throws KeyStoreException {
        final PublicKey result;
        final Certificate certificate = keystore.getCertificate(keyAlias);
        if (certificate == null) {
            result = null;
        } else {
            result = certificate.getPublicKey();
        }
        return result;
    }

    @Override
    public PrivateKey aquirePrivateKey(String alias, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return (PrivateKey) keystore.getKey(alias, password);
    }

    @Override
    public void releasePrivateKey(PrivateKey privateKey) {
        // NOP
    }

    @Override
    public List<TokenEntry> getEntries()
        throws KeyStoreException {
        final Enumeration<String> e = keystore.aliases();
        final List<TokenEntry> result = new LinkedList<>();
        
        while (e.hasMoreElements()) {
            final String keyAlias = e.nextElement();
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

        return result;
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
            if (chain != null && chain.length > 0) {
                final PublicKey pubKey = chain[0].getPublicKey();
                String keyAlgorithm =
                        AlgorithmTools.getKeyAlgorithm(pubKey);
                if (keyAlgorithm == null) {
                    keyAlgorithm = pubKey.getAlgorithm();
                }
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
                } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | ProviderException ex) {
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
