/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.p11ng.common.cryptotoken;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.pkcs11.jacknji11.CKA;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.NoSuchAliasException;
import org.signserver.p11ng.common.provider.CryptokiDevice.Slot;
import org.signserver.p11ng.common.provider.NJI11ReleasebleSessionSecretKey;
import org.signserver.p11ng.common.provider.SlotEntry;
import org.signserver.server.IServices;
import org.signserver.server.cryptotokens.AllowedMechanisms;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_ALGORITHM;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_PUBLIC_EXPONENT;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_SIGNINGS;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.INFO_KEY_SPECIFICATION;
import static org.signserver.server.cryptotokens.CryptoTokenHelper.getNoOfSignings;
import org.signserver.server.cryptotokens.KeyStoreDelegator;
import org.signserver.server.cryptotokens.TokenEntry;
import static org.signserver.server.cryptotokens.TokenEntry.TYPE_PRIVATEKEY_ENTRY;
import static org.signserver.server.cryptotokens.TokenEntry.TYPE_SECRETKEY_ENTRY;

/**
 * Implementation of KeyStoreDelegator using a JackNJI11 slot instance.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class JackNJI11KeyStoreDelegator implements KeyStoreDelegator {
    /** Logger for this class **/
    private static final Logger LOG = Logger.getLogger(JackNJI11KeyStoreDelegator.class);

    private final Slot slot;

    public JackNJI11KeyStoreDelegator(final Slot slot) {
        this.slot = slot;
    }
    
    @Override
    public boolean containsAlias(String alias) throws KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet");
    }

    @Override
    public void deleteEntry(String alias) throws KeyStoreException {
        slot.removeKey(alias);
    }

    @Override
    public PublicKey getPublicKey(String keyAlias) throws KeyStoreException {
        final PublicKey result;
        final Certificate certificate = slot.getCertificate(keyAlias);
        if (certificate == null) {
            result = null;
        } else {
            result = certificate.getPublicKey();
        }
        return result;
    }

    @Override
    public PrivateKey aquirePrivateKey(String alias, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CryptoTokenOfflineException {
        return slot.aquirePrivateKey(alias);
    }
    
    @Override
    public void releasePrivateKey(PrivateKey privateKey) {
        slot.releasePrivateKey(privateKey);
    }

    @Override
    public List<TokenEntry> getEntries() throws KeyStoreException, CryptoTokenOfflineException {
        final ArrayList<TokenEntry> tokenEntries = new ArrayList<>();
        final Enumeration<SlotEntry> e = slot.aliases(); // We assume the order is the same for every call unless entries has been added or removed

        while (e.hasMoreElements()) {
            final SlotEntry slotEntry  = e.nextElement();                
            final String keyAlias = slotEntry.getAlias();
            final String type;

            if (slotEntry.getType().equals(TYPE_PRIVATEKEY_ENTRY)) {
                type = TYPE_PRIVATEKEY_ENTRY;
            } else if (slotEntry.getType().equals(TYPE_SECRETKEY_ENTRY)) {
                type = TYPE_SECRETKEY_ENTRY;
            } else {
                type = null;
            }                            

            TokenEntry entry = new TokenEntry(keyAlias, type);
            tokenEntries.add(entry);
        }
        
        return tokenEntries;
    }



    @Override
    public void addAdditionalDataToEntry(TokenEntry entry, char[] authCode, IServices services)
            throws KeyStoreException, CryptoTokenOfflineException {
        final Map<String, String> info = new HashMap<>();
        final String type = entry.getType();
        final String keyAlias = entry.getAlias();
        
        final ChainLookup chainLookup = new ChainLookup() {
            @Override
            public List<Certificate> getChain(String keyAlias, Slot keyStore) {
                return keyStore.getCertificateChain(keyAlias);
            }
        };
        
        /*try {
            Date creationDate = keyStore.getCreationDate(keyAlias);
            entry.setCreationDate(creationDate);
        } catch (ProviderException ex) {} // NOPMD: We ignore if it is not supported
         */
        if (TYPE_PRIVATEKEY_ENTRY.equals(type)) {
            Certificate[] chain = null;
            try {
                chain = chainLookup.getChain(keyAlias, slot).toArray(new Certificate[0]);
            } catch (NoSuchAliasException ex) {
                LOG.error("No certificate chain for alias: " + keyAlias, ex);
            }
            if (chain != null && chain.length > 0) {
                final PublicKey publicKey = chain[0].getPublicKey();
                setPublicKeyInfo(info, publicKey);
                info.put(INFO_KEY_SIGNINGS, String.valueOf(getNoOfSignings(publicKey, services)));
            } else {
                final PublicKey publicKey = slot.getPublicKey(keyAlias);
                if (publicKey != null) {
                    setPublicKeyInfo(info, publicKey);
                }
            }
            try {
                entry.setParsedChain(chain);
            } catch (CertificateEncodingException ex) {
                LOG.error("Certificate could not be encoded for alias: " + keyAlias, ex);
            }

            CKA allowedMechanismAttribute = slot.getAllowedMechanismAttribute(keyAlias, CKA.ALLOWED_MECHANISMS);
            if (allowedMechanismAttribute != null && allowedMechanismAttribute.getValue() != null) {
                info.put(CryptoTokenHelper.INFO_KEY_ALLOWED_MECHANISMS, AllowedMechanisms.fromBinaryEncoding(allowedMechanismAttribute.getValue()).toPropertyValue());
            }

            StringBuilder sb = new StringBuilder();
            slot.securityInfo(keyAlias, sb);
            info.put(CryptoTokenHelper.INFO_KEY_PKCS11_ATTRIBUTES, sb.toString().replace("  ", "\n"));
        } else if (TYPE_SECRETKEY_ENTRY.equals(type)) {
            SecretKey secretKey = slot.getSecretKey(keyAlias);
            if (secretKey != null) {
                info.put(INFO_KEY_ALGORITHM, secretKey.getAlgorithm());
                info.put(INFO_KEY_SPECIFICATION, ((NJI11ReleasebleSessionSecretKey) secretKey).getKeySpec());
            }
            final Certificate[] chain = new Certificate[0];
            try {
                entry.setParsedChain(chain);
            } catch (CertificateEncodingException ex) {
                LOG.error("Certificate could not be encoded for alias: " + keyAlias, ex);
            }
        }
        entry.setInfo(info);
    }

    @Override
    public void setKeyEntry(String alias, PrivateKey key, char[] authCode, Certificate[] certificate) throws KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    private static void setPublicKeyInfo(Map<String, String> infoMap, PublicKey publicKey) {
        final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(publicKey);
        infoMap.put(INFO_KEY_ALGORITHM, keyAlgorithm);
        infoMap.put(INFO_KEY_SPECIFICATION, AlgorithmTools.getKeySpecification(publicKey));
        if (AlgorithmConstants.KEYALGORITHM_RSA.equals(keyAlgorithm)) {
            final RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
            infoMap.put(INFO_KEY_PUBLIC_EXPONENT, rsaKey.getPublicExponent().toString(10));
        }
    }
    
    private interface ChainLookup {
        List<Certificate> getChain(String keyAlias, Slot keyStore) throws NoSuchAliasException, CryptoTokenOfflineException;
    }
}
