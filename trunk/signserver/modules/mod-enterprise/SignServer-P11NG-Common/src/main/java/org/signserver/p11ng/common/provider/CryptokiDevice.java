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
package org.signserver.p11ng.common.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKC;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.LongRef;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.p11ng.common.FindObjectsCallParamsHolder;
import org.signserver.p11ng.common.GetAttributeValueCallParamsHolder;
import org.signserver.p11ng.common.P11NGSlotStore;
import static org.signserver.server.cryptotokens.TokenEntry.TYPE_PRIVATEKEY_ENTRY;
import static org.signserver.server.cryptotokens.TokenEntry.TYPE_SECRETKEY_ENTRY;
import static org.signserver.p11ng.common.P11NGStoreConstants.*;

/**
 * Instance managing the cryptoki library and allowing access to its slots.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CryptokiDevice {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CryptokiDevice.class);

    private final CEi c;
    private final JackNJI11Provider provider;
    private final ArrayList<Slot> slots = new ArrayList<>();
    private final HashMap<Long, Slot> slotMap = new HashMap<>();    
    
    private static final int MAX_CHAIN_LENGTH = 100;
    
    CryptokiDevice(CEi c, JackNJI11Provider provider) {
        if (c == null) {
            throw new NullPointerException("c must not be null");
        }
        this.c = c;
        this.provider = provider;
        try {
            if (LOG.isTraceEnabled()) {
                LOG.trace("c.Initialize()");
            }
            c.Initialize();
        } catch (CKRException ex) {
            if (ex.getCKR() == CKR.CRYPTOKI_ALREADY_INITIALIZED) {
                LOG.info("Cryptoki already initialized");
            } else {
                throw ex;
            }
        }
        
        // TODO: Assumes static slots
        if (LOG.isTraceEnabled()) {
            LOG.trace("c.GetSlotList(true)");
        }
        final long[] slotsWithTokens = c.GetSlotList(true);
        for (long slotId : slotsWithTokens) {
            Slot s = new Slot(slotId);
            slots.add(s);
            slotMap.put(slotId, s);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("slots: " + slots);
        }
    }
    
    public Slot getSlot(final Long slotId) {
        return slotMap.get(slotId);
    }
    
    public Slot getSlotByIndex(final int slotIndex) {
        return slots.get(slotIndex);
    }
    
    public List<Slot> getSlots() {
        return Collections.unmodifiableList(slots);
    }
    
    public class Slot {
        private final long id;
        private final LinkedList<Long> activeSessions = new LinkedList<>();
        private final LinkedList<Long> idleSessions = new LinkedList<>();
        private Long loginSession;
        private final P11NGSlotStore cache;
        private boolean useCache;
        
        public synchronized boolean isUseCache() {
            return useCache;
        }

        public synchronized void setUseCache(boolean useCache) {
            this.useCache = useCache;
        }
        
        private Slot(final long id) {
            this.id = id;
            this.cache = new P11NGSlotStore();
        }
        
        final protected CEi getCryptoki() {
            return c;
        }
        
        protected synchronized long aquireSession() {
            Long session;
            if (!idleSessions.isEmpty()) {
                session = idleSessions.pop();
                if (LOG.isTraceEnabled()) {
                    LOG.trace("Popped session " + session);
                }
            } else {
                session = c.OpenSession(id, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
                if (LOG.isTraceEnabled()) {
                    LOG.trace("c.OpenSession : " + session);
                }
            }
            activeSessions.add(session);
            
            if (LOG.isTraceEnabled()) {
                LOG.trace(this);
            }
            
            return session;
        }
        
        protected synchronized void releaseSession(final long session) {
            // TODO: Checks
            if (!activeSessions.remove(session)) {
                LOG.error("Releasing session not active: " + session);
            }
            idleSessions.push(session);
            
            if (LOG.isTraceEnabled()) {
                LOG.trace("Released session " + session + ", " + this);
            }
        }
        
        protected synchronized void closeSession(final long session) {
            // TODO: Checks
            if (LOG.isTraceEnabled()) {
                LOG.trace("c.CloseSession(" + session + ")");
            }
            c.CloseSession(session);
            activeSessions.remove(session);
            if (idleSessions.contains(session)) {
                LOG.error("Session that was closed is still marked as idle: " + session);
            }
            
            if (LOG.isTraceEnabled()) {
                LOG.trace(this);
            }
        }

        public synchronized void login(final String pin) {
            // Note: We use a dedicated session for login so it will remain logged in
            if (loginSession == null) {
                loginSession = aquireSession();
            }
            if (LOG.isTraceEnabled()) {
                LOG.trace("c.Login(" + loginSession + ")");
            }
            c.Login(loginSession, CKU.USER, pin.getBytes(StandardCharsets.UTF_8));
        }

        public synchronized void logout() {
            try {
                if (loginSession == null) {
                    loginSession = aquireSession();
                }
                if (LOG.isTraceEnabled()) {
                    LOG.trace("c.Logout(" + loginSession + ")");
                }
                c.Logout(loginSession);
            } finally {
                if (loginSession != null) {
                    releaseSession(loginSession);
                    loginSession = null;
                }
            }
        }
        
        public PrivateKey unwrapPrivateKey(final byte[] wrappedPrivateKey, final String unwrapkey, final long wrappingCipher) {
            Long session = aquireSession();
            // Find unWrapKey
            long[] secretObjects = findSecretKeyObjectsByLabel(session, unwrapkey);

            final long unWrapKey;
            if (secretObjects.length == 1) {
                unWrapKey = secretObjects[0];
            } else if (secretObjects.length > 1) {
                throw new RuntimeException("More than one secret key found with alias: " + unwrapkey); // TODO
            } else {
                throw new RuntimeException("No such secret key found: " + unwrapkey); // TODO
            }

            CKA[] unwrappedPrivateKeyTemplate = new CKA[]{
                new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
                new CKA(CKA.KEY_TYPE, CKK.RSA),
                new CKA(CKA.PRIVATE, true),
                new CKA(CKA.DECRYPT, true),
                new CKA(CKA.SIGN, true),
                new CKA(CKA.SENSITIVE, true),
                new CKA(CKA.EXTRACTABLE, true),
            };

            long privateKey = getUnwrappedPrivateKey(session, wrappingCipher, unWrapKey, wrappedPrivateKey, unwrappedPrivateKeyTemplate);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unwrapped key: " + privateKey + ", unwrap key: " + 
                          unWrapKey + ", session: " + session);
            }

            NJI11StaticSessionPrivateKey result = new NJI11StaticSessionPrivateKey(session, privateKey, this, true);
            return result;
        }
        
        public void releasePrivateKey(PrivateKey privateKey) {
            // TODO: Checks
            if (privateKey instanceof NJI11StaticSessionPrivateKey) {
                NJI11StaticSessionPrivateKey priv = (NJI11StaticSessionPrivateKey) privateKey;
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Releasing private key: " + ((NJI11StaticSessionPrivateKey) privateKey).getObject() +
                              ", session: " + priv.getSession());
                }

                // Unwrapped keys should be removed
                if (priv.isRemovalOnRelease()) {
                    c.DestroyObject(priv.getSession(), priv.getObject());
                }

                // Release the session
                releaseSession(priv.getSession());
            } else {
                LOG.warn("Not a closable PrivateKey: " + privateKey.getClass().getName());
            }
        }
        
        @Override
        public String toString() {
            return "Slot{" + "id=" + id + ", activeSessions=" + activeSessions + ", idleSessions=" + idleSessions + '}';
        }
        
        public SecretKey getSecretKey(String alias) {
            Long session = null;
            String keySpec = "n/a";
            try {
                session = aquireSession();

                // Searching by LABEL is sufficient but using SECRET_KEY also just to be extra safe
                long[] secretObjects = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.SECRET_KEY), new CKA(CKA.LABEL, alias));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Secret Objects: " + Arrays.toString(secretObjects));
                }
                if (secretObjects.length > 1) {
                    LOG.warn("More than one secret key with CKA_LABEL=" + alias);
                } else if (secretObjects.length == 1) {
                    CKA keyTypeObj = c.GetAttributeValue(session, secretObjects[0], CKA.KEY_TYPE);
                    String keyType = CKK.L2S(keyTypeObj.getValueLong());

                    CKA keySpecObj = c.GetAttributeValue(session, secretObjects[0], CKA.VALUE_LEN);
                    if (keySpecObj != null && keySpecObj.getValueLong() != null) { // This check is required as keySpecObj.getValueLong() may be null in case of DES keys for some HSMs like SOFT HSM
                        keySpec = String.valueOf(keySpecObj.getValueLong() * 8);
                    }

                    return new NJI11ReleasebleSessionSecretKey(secretObjects[0], keyType, keySpec, this);
                }
                return null;
            } finally {
                if (session != null) {
                    releaseSession(session);   // XXX Shouldn't we use a static session instead, now the key can't be used!
                }
            }
        }
        
        /**
         * Get a PrivateKey instance including a dedicated session.
         *
         * Note: Caller must eventually call releasePrivateKey(PrivateKey)
         *
         * @param alias of key entry
         * @return  The PrivateKey reference or null if no such key exists
         * @throws CryptoTokenOfflineException
         */
        public PrivateKey aquirePrivateKey(String alias) throws CryptoTokenOfflineException { // TODO: Support alias that is hexademical or label or Id
            Long session;
            
            try {
                session = aquireSession();
            } catch (CKRException ex) { // throw CryptoTokenOfflineException when device error
                throw new CryptoTokenOfflineException(ex);
            }
            
            // Find certificate by label
            long[] certificateRefs = findCertificateObjectsByLabel(session, alias);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Certificate Objects: " +  Arrays.toString(certificateRefs));
            }
            
            if (certificateRefs.length > 0) {
                CKA ckaId = getAttributeCertificateID(session, certificateRefs[0]);
                long[] privateObjects = findPrivateKeyObjectsByID(session, ckaId.getValue());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Private Objects: " +  Arrays.toString(privateObjects));
                }
                if (privateObjects.length == 0) {
                    LOG.warn("No private key object with CKA_ID=0x" + Hex.toHexString(ckaId.getValue()));
                } else if (privateObjects.length > 1) {
                    LOG.warn("More than one private key object sharing CKA_ID=0x" + Hex.toHexString(ckaId.getValue()));
                } else {
                    return new NJI11StaticSessionPrivateKey(session, privateObjects[0], this, false);
                }
            }
            closeSession(session);
            return null;
        }
        
        /**
         * Get a PrivateKey instance that dynamically obtains a session when the Signature instance is being initialized and which is released 
         * automatically when the signing is finished.
         * 
         * Note: If Signature instance is being initialized but never carried out the session might remain.
         * @param alias of key entry
         * @return The PrivateKey reference or null if no such key exists
         */
        public PrivateKey getReleasableSessionPrivateKey(String alias) {  // TODO: Support alias that is hexademical or label or Id
            Long session = null;
            try {
                session = aquireSession();
                
                // Find certificate by label
                long[] certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Certificate Objects: " +  Arrays.toString(certificateRefs));
                }

                if (certificateRefs.length > 0) {
                    CKA ckaId = c.GetAttributeValue(session, certificateRefs[0], CKA.ID);
                    long[] privateObjects = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.ID, ckaId.getValue()));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Private Objects: " +  Arrays.toString(privateObjects));
                    }
                    if (privateObjects.length > 1) {
                        LOG.warn("More than one private key object sharing CKA_ID=0x" + Hex.toHexString(ckaId.getValue()));
                    } else {
                        return new NJI11ReleasebleSessionPrivateKey(privateObjects[0], this);
                    }
                }
                return null;
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        public PublicKey getPublicKey(String alias) { // TODO: Support alias that is hexademical or label or Id
            Long session = null;
            try {
                session = aquireSession();
                
                // Find certificate by label
                long[] certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Certificate Objects: " +  Arrays.toString(certificateRefs));
                }

                if (certificateRefs.length > 0) {
                    CKA ckaId = c.GetAttributeValue(session, certificateRefs[0], CKA.ID);
                    if (ckaId != null) {
                        long[] publicObjects = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PUBLIC_KEY), new CKA(CKA.ID, ckaId.getValue()));
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Public Objects: " +  Arrays.toString(publicObjects));
                        }
                        if (publicObjects.length > 1) {
                            LOG.warn("More than one public key object sharing CKA_ID=0x" + Hex.toHexString(ckaId.getValue()));
                        } else if (publicObjects.length == 1) {
                            long object = publicObjects[0];
                            CKA publicValue = c.GetAttributeValue(session, object, CKA.MODULUS);
                            final byte[] modulusBytes = publicValue.getValue();
                            publicValue = c.GetAttributeValue(session, object, CKA.PUBLIC_EXPONENT);
                            final byte[] publicExponentBytes = publicValue.getValue();

                            final BigInteger n = new BigInteger(1, modulusBytes);
                            final BigInteger e = new BigInteger(1, publicExponentBytes);

                            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
                            return publicKey;
                        }
                    }
                }
                return null;
            } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                throw new RuntimeException(ex);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        public JackNJI11Provider getProvider() {
            return provider;
        }

        public GeneratedKeyData generateWrappedKey(String wrapKeyAlias, String keyAlgorithm, String keySpec, long wrappingCipher) {
            
            if (!"RSA".equals(keyAlgorithm)) {
                throw new IllegalArgumentException("Only RSA supported as key algorithm");
            }
            final int keyLength = Integer.parseInt(keySpec);
            
            Long session = null;
            try {
                session = aquireSession();

                // Find wrapKey
                long[] secretObjects = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.SECRET_KEY), new CKA(CKA.LABEL, wrapKeyAlias));
                
                long wrapKey = -1;
                if (secretObjects.length == 1) {
                    wrapKey = secretObjects[0];
                } else {
                    if (secretObjects.length < 0) {
                        throw new RuntimeException("No such secret key found with alias: " + wrapKeyAlias); // TODO
                    }
                    if (secretObjects.length > 1) {
                        throw new RuntimeException("More than one secret key found with alias: " + wrapKeyAlias); // TODO
                    }
                }                

                long[] mechanisms = c.GetMechanismList(id);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Mechanisms: " + toString(mechanisms));
                }

                CKA[] publicKeyTemplate = new CKA[] {
                    new CKA(CKA.ENCRYPT, true),
                    new CKA(CKA.VERIFY, true),
                    new CKA(CKA.WRAP, true),
                    new CKA(CKA.MODULUS_BITS, keyLength),
                    new CKA(CKA.PUBLIC_EXPONENT, new BigInteger("65537").toByteArray()),
                };

                CKA[] privateKeyTemplate = new CKA[] {
                    new CKA(CKA.PRIVATE, true),
                    new CKA(CKA.SENSITIVE, true),
                    new CKA(CKA.DECRYPT, true),
                    new CKA(CKA.SIGN, true),
                    new CKA(CKA.UNWRAP, true),
                    new CKA(CKA.EXTRACTABLE, true)
                };

                LongRef publicKeyRef = new LongRef();
                LongRef privateKeyRef = new LongRef();

                c.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), publicKeyTemplate, privateKeyTemplate, publicKeyRef, privateKeyRef);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Generated public key: " + publicKeyRef.value + " and private key: " + privateKeyRef.value);
                }

                CKA publicValue = c.GetAttributeValue(session, publicKeyRef.value, CKA.MODULUS);

                final byte[] modulusBytes = publicValue.getValue();

                publicValue = c.GetAttributeValue(session, publicKeyRef.value, CKA.PUBLIC_EXPONENT);
                final byte[] publicExponentBytes = publicValue.getValue();

                final BigInteger n = new BigInteger(1, modulusBytes);
                final BigInteger e = new BigInteger(1, publicExponentBytes);
                try {
                    RSAPublicKey publicKey = new RSAPublicKey(n, e);
                    
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Public key: " + Base64.toBase64String(publicKey.getEncoded()));
                    }

                    CKM cipherMechanism = new CKM(wrappingCipher); // OK with nCipher
//                    CKM cipherMechanism = new CKM(0x00001091); // SoftHSM2+patched-botan
                    
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Using mechanism: " + cipherMechanism);
                    }
                    
                    byte[] wrapped = c.WrapKey(session, cipherMechanism, wrapKey, privateKeyRef.value);       // TODO cipher
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Wrapped private key: " + Base64.toBase64String(wrapped));
                    }

                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption), publicKey.getEncoded()).getEncoded())); // TODO: Maybe not the shortest

                    return new GeneratedKeyData(wrapped, pubKey);
                } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException ex) {
                    throw new RuntimeException(ex); // TODO
                }
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        public void generateKeyPair(String keyAlgorithm, String keySpec, String alias, boolean publicKeyToken, Map<Long, Object> overridePublic, Map<Long, Object> overridePrivate, CertificateGenerator certGenerator, boolean storeCertificate) throws CertificateEncodingException, CertificateException, OperatorCreationException {
            Long session = null;
            try {
                session = aquireSession();

                // Check if any key with provided alias exists 
                long[] objs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.LABEL, alias));
                if (objs.length != 0) {
                    throw new IllegalArgumentException("Key with label " + alias + " already exists");
                }
                objs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.ID, alias.getBytes(StandardCharsets.UTF_8)));
                if (objs.length != 0) {
                    throw new IllegalArgumentException("Key with ID " + alias + " already exists");
                }

                if (!"RSA".equals(keyAlgorithm)) {
                    throw new IllegalArgumentException("Only RSA supported as key algorithm");
                }
                final int keyLength = Integer.parseInt(keySpec);

                long[] mechanisms = c.GetMechanismList(id);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Mechanisms: " + toString(mechanisms));
                }

                final HashMap<Long, Object> publicTemplate = new HashMap<>();
                publicTemplate.put(CKA.TOKEN, publicKeyToken);
                publicTemplate.put(CKA.ENCRYPT, false);
                publicTemplate.put(CKA.VERIFY, true);
                publicTemplate.put(CKA.WRAP, false);
                publicTemplate.put(CKA.MODULUS_BITS, keyLength);
                publicTemplate.put(CKA.PUBLIC_EXPONENT, new BigInteger("65537").toByteArray());
                publicTemplate.put(CKA.LABEL, ("pub-" + alias).getBytes(StandardCharsets.UTF_8));
                publicTemplate.put(CKA.ID, alias.getBytes(StandardCharsets.UTF_8));

                final HashMap<Long, Object> privateTemplate = new HashMap<>();
                privateTemplate.put(CKA.TOKEN, true);
                privateTemplate.put(CKA.PRIVATE, true);
                privateTemplate.put(CKA.SENSITIVE, true);
                privateTemplate.put(CKA.DECRYPT, false);
                privateTemplate.put(CKA.SIGN, true);
                privateTemplate.put(CKA.UNWRAP, false);
                privateTemplate.put(CKA.EXTRACTABLE, false);
                privateTemplate.put(CKA.LABEL, ("priv-" + alias).getBytes(StandardCharsets.UTF_8));
                privateTemplate.put(CKA.ID, alias.getBytes(StandardCharsets.UTF_8));

                // Override attributes
                publicTemplate.putAll(overridePublic);
                privateTemplate.putAll(overridePrivate);

                final CKA[] publicTemplateArray = toCkaArray(publicTemplate);
                final CKA[] privateTemplateArray = toCkaArray(privateTemplate);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Public Template:\n" + Arrays.toString(publicTemplateArray));
                    LOG.debug("Private Template:\n" + Arrays.toString(privateTemplateArray));
                }

                LongRef publicKeyRef = new LongRef();
                LongRef privateKeyRef = new LongRef();

                c.GenerateKeyPair(session, new CKM(CKM.RSA_PKCS_KEY_PAIR_GEN), publicTemplateArray, privateTemplateArray, publicKeyRef, privateKeyRef);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Generated public key: " + publicKeyRef.value + " and private key: " + privateKeyRef.value);
                }

                CKA publicValue = c.GetAttributeValue(session, publicKeyRef.value, CKA.MODULUS);

                final byte[] modulusBytes = publicValue.getValue();

                publicValue = c.GetAttributeValue(session, publicKeyRef.value, CKA.PUBLIC_EXPONENT);
                final byte[] publicExponentBytes = publicValue.getValue();

                final BigInteger n = new BigInteger(1, modulusBytes);
                final BigInteger e = new BigInteger(1, publicExponentBytes);
                try {
                    RSAPublicKey publicKey = new RSAPublicKey(n, e);

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Public key: " + Base64.toBase64String(publicKey.getEncoded()));
                    }

                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption), publicKey.getEncoded()).getEncoded())); // TODO: Maybe not the shortest

                    KeyPair keyPair = new KeyPair(pubKey, new NJI11StaticSessionPrivateKey(session, privateKeyRef.value, this, false));

                    if (certGenerator != null) {
                        X509Certificate cert = certGenerator.generateCertificate(keyPair, provider); // Note: Caller might want to store the certificate so we need to call this even if storeCertificate==false
                        
                        if (storeCertificate) {
                            CKA[] cert0Template = new CKA[] {
                                new CKA(CKA.CLASS, CKO.CERTIFICATE),
                                new CKA(CKA.CERTIFICATE_TYPE, CKC.CKC_X_509),
                                new CKA(CKA.TOKEN, true),
                                new CKA(CKA.LABEL, alias),
                                new CKA(CKA.SUBJECT, ((X509Certificate) cert).getSubjectX500Principal().getEncoded()),
                                new CKA(CKA.ID, alias),
                                new CKA(CKA.VALUE, cert.getEncoded())
                            };
                            c.CreateObject(session, cert0Template);
                        }
                    }
                } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException ex) {
                    throw new RuntimeException(ex); // TODO
                }
                
                // remove negative (empty) cached search results if exists as key is created actually now
                if (useCache) {
                    cache.removeObjectsSearchResultByLabel(alias);
                }

            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
        
        private CKA[] toCkaArray(HashMap<Long, Object> map) {
            final List<CKA> result = new ArrayList<>(map.size());
            for (Map.Entry<Long, Object> entry: map.entrySet()) {
                result.add(new CKA(entry.getKey(), entry.getValue()));
            }
            return result.toArray(new CKA[0]);
        }

        public void generateKey(long keyAlgorithm, int keySpec, String alias) {
            Long session = null;
            try {
                session = aquireSession();

                // Check if any key with provided alias exists 
                long[] objs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.LABEL, alias));
                if (objs.length != 0) {
                    throw new IllegalArgumentException("Key with label " + alias + " already exists");
                }
                objs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.ID, alias.getBytes(StandardCharsets.UTF_8)));
                if (objs.length != 0) {
                    throw new IllegalArgumentException("Key with ID " + alias + " already exists");
                }
                
                final CKA[] secretKeyTemplate;
                
                if (keyAlgorithm == CKM.DES_KEY_GEN || keyAlgorithm == CKM.DES2_KEY_GEN || keyAlgorithm == CKM.DES3_KEY_GEN) {
                    long newMechanism = getMechanismForDESKey(keyAlgorithm, keySpec);
                    keyAlgorithm = newMechanism;
                    // Don't set CKA.VALUE_LEN for DES key as length is fixed
                    secretKeyTemplate = new CKA[]{
                        new CKA(CKA.TOKEN, true),
                        new CKA(CKA.ID, alias.getBytes(StandardCharsets.UTF_8)),
                        new CKA(CKA.WRAP, true),
                        new CKA(CKA.UNWRAP, true),
                        new CKA(CKA.SENSITIVE, true),
                        new CKA(CKA.EXTRACTABLE, false),
                        new CKA(CKA.LABEL, alias.getBytes(StandardCharsets.UTF_8))};
                } else {
                    secretKeyTemplate = new CKA[]{
                        new CKA(CKA.TOKEN, true),
                        new CKA(CKA.ID, alias.getBytes(StandardCharsets.UTF_8)),
                        new CKA(CKA.WRAP, true),
                        new CKA(CKA.UNWRAP, true),
                        new CKA(CKA.SENSITIVE, true),
                        new CKA(CKA.EXTRACTABLE, false),
                        new CKA(CKA.VALUE_LEN, keySpec/8),
                        new CKA(CKA.LABEL, alias.getBytes(StandardCharsets.UTF_8))};
                }                

                long newObject = c.GenerateKey(session, new CKM(keyAlgorithm), secretKeyTemplate);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Generated secret key: " + newObject + " with alias " + alias);
                }
                
                // remove negative (empty) cached search results if exists as key is created actually now
                if (useCache) {
                    cache.removeObjectsSearchResultByLabel(alias);
                }
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }       
                
        private long getMechanismForDESKey(long keyAlgorithm, int keySpec) {
            Long mechanism = null;
            switch ((int) keyAlgorithm) {
                case (int) CKM.DES_KEY_GEN:
                    if ((keySpec != 64) && (keySpec != 56)) {
                        throw new IllegalArgumentException("DES key length is invalid");
                    }
                    mechanism = CKM.DES_KEY_GEN;
                    break;
                case (int) CKM.DES2_KEY_GEN:
                case (int) CKM.DES3_KEY_GEN:
                    if ((keySpec == 112) || (keySpec == 128)) {
                        mechanism = CKM.DES2_KEY_GEN;
                    } else if ((keySpec == 168) || (keySpec == 192)) {
                        mechanism = CKM.DES3_KEY_GEN;
                    } else {
                        throw new IllegalArgumentException("DESede key length is invalid");
                    }
                    break;
            }
            return mechanism;
        }
        
        public boolean removeKey(String alias) {
            Long session = null;
            try {
                session = aquireSession();

                // 1. Search for a certificate
                long[] certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Certificate Objects: " +  Arrays.toString(certificateRefs));
                }
                
                if (certificateRefs.length > 0) {
                    boolean allDeleted = true;
                    // Find those that have matching private keys
                    for (long certRef : certificateRefs) {
                        CKA ckaId = c.GetAttributeValue(session, certRef, CKA.ID);
                        if (ckaId == null) {
                            allDeleted = false;
                        } else {
                            long[] privRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.ID, ckaId.getValue()));
                            if (privRefs.length > 1) {
                                LOG.warn("More than one private key object sharing CKA_ID=0x" + Hex.toHexString(ckaId.getValue()));
                                allDeleted = false;
                            } else if (privRefs.length == 1) {
                                // Remove private key
                                removeKeyObject(session, privRefs[0]);                               
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("Destroyed private key: " + privRefs[0] + " for alias " + alias);
                                }
                                
                                // Now find and remove the certificate and its CA certificates if they are not used
                                removeCertificateAndChain(session, certRef, new HashSet<String>());
                                
                                // If the private key is not there anymore, let's call it a success
                                long[] objectsAfterDeletion = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.ID, ckaId.getValue()));
                                allDeleted = allDeleted && objectsAfterDeletion.length == 0;
                            }
                        }
                    }
                    return allDeleted;
                } else {
                    // Find key
                    long[] objs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.SECRET_KEY), new CKA(CKA.LABEL, alias));

                    if (objs.length >= 1) {
                        for (long object : objs) {
                            // Destroy secret key
                            removeKeyObject(session, object);
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Destroyed Key: " + object + " with alias " + alias);
                            }
                        }
                    } else {
                        throw new IllegalArgumentException("key could not be found: " + alias + " so not deleted");
                    }

                    // Check whether key exists after deletion 
                    long[] objectsAfterDeletion = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.LABEL, alias));
                    return objectsAfterDeletion.length == 0;
                }
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
                
        private String toString(long[] mechanisms) {
            final StringBuilder results = new StringBuilder();
            for (long l : mechanisms) {
                results.append(CKM.L2S(l));
                results.append(" ");
            }
            return results.toString();
        }
        
        private void removeCertificateAndChain(long session, long certRef, final Set<String> keptSubjects) {
            // Remove old certificate objects
             //keptSubjects: Subject DN of certificates that was not deleted
            long[] certificateRefs;
            int i = 0;
            for (; i < MAX_CHAIN_LENGTH; i++) {
                CKA ckaSubject = c.GetAttributeValue(session, certRef, CKA.SUBJECT);
                CKA ckaIssuer = c.GetAttributeValue(session, certRef, CKA.ISSUER);

                // 4. Find any certificate objects having this object as issuer, if no found delete the object
                certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.ISSUER, ckaSubject.getValue()));
                if (certificateRefs.length == 0 || (certificateRefs.length == 1 && certificateRefs[0] == certRef)) {
                    removeCertificateObject(session, certRef);
                } else {
                    keptSubjects.add(Hex.toHexString(ckaSubject.getValue()));
                }

                // 5. Unless the certificate is self-signed, find the issuer certificate object or if no found skip to 7
                if (Arrays.equals(ckaSubject.getValue(), ckaIssuer.getValue())) {
                    break;
                } else {
                    certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.SUBJECT, ckaIssuer.getValue()));

                    if (certificateRefs.length == 0) {
                        break;
                    } else if (certificateRefs.length > 1) {
                        LOG.warn("Multiple certificate objects sharing the same CKA_SUBJECT: " + Hex.toHexString(ckaIssuer.getValue()));
                    }
                    // 6. Do step 4 for that object
                    certRef = certificateRefs[0];
                }
            }
            // Either there was more than 100 certificates in the chain or there was some object having an issuer pointing to an earlier object,
            // so lets bail out instead of looping forever if this happens.
            if (i == MAX_CHAIN_LENGTH) {
                LOG.warn("More than " + MAX_CHAIN_LENGTH + " certificates in chain (or circular subject/issuer chain). All certificates might not have been removed."); 
            }
        }

        /**
         * Import a certificate chain for a private key to the token.
         *
         * Known limitations:
         * - It is not supported to have multiple different CA certificates with the same DN. The existing certificate will be replaced.
         * 
         * Operations that needs to be performed:
         * - Remove previous certificates unless they (i.e. CA certificates) are used by any other key entry
         * - Add the new certificates
         *
         * Algorithm:
         * 1. Find certificate object with provided CKA_LABEL=alias
         * 2. Get the CKA_ID
         * 3. Find the matching private key (just as sanity check)
         *
         * 4. Find any certificate objects having this object as issuer, if no found delete the object otherwise store the name of the subject
         * 5. Unless the certificate is self-signed, find the issuer certificate object or if no found skip to 7
         * 6. Do step 4 for that object
         *
         * 7. Add the new certificate objects, excluding those subjects that was not deleted in step 4
         *
         * @param certChain
         * @param alias 
         */
        public void importCertificateChain(List<Certificate> certChain, String alias) {
            Long session = null;
            try {
                // TODO: Make some sanity checks on the certificates
                
                session = aquireSession();
                
                // 1. Find certificate object
                long[] certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Certificate Objects: " +  Arrays.toString(certificateRefs));
                }
                if (certificateRefs.length < 1) {
                    throw new IllegalArgumentException("No such key");
                }

                // 2. Get the CKA_ID
                CKA ckaId = c.GetAttributeValue(session, certificateRefs[0], CKA.ID);

                // 3. Find the matching private key (just as sanity check)
                long[] privateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.ID, ckaId.getValue()));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Private Objects: " +  Arrays.toString(privateRefs));
                }
                if (privateRefs.length < 1) {
                    throw new IllegalArgumentException("No such key");
                }
                if (privateRefs.length > 1) {
                    LOG.error("Warning: More than one private key objects available with CKA_ID: 0x" + Hex.toHexString(ckaId.getValue()));
                }

                // 4. 5. 6. Remove old certificate objects
                final Set<String> keptSubjects = new HashSet<>(); // Subject DN of certificates that was not deleted
                removeCertificateAndChain(session, certificateRefs[0], keptSubjects);

                // 7. Add the new certificate objects, excluding those subjects that was not deleted in step 4.
                // Following the convention used by Oracle Java PKCS#11 Reference Guide
                if (!certChain.isEmpty()) {
                    final Iterator<Certificate> iterator = certChain.iterator();
                    X509Certificate cert = (X509Certificate) iterator.next();

                    byte[] subject = cert.getSubjectX500Principal().getEncoded();
                    
                    CKA[] cert0Template = new CKA[] {           // TODO: Add support for specifying attributes like for keygen
                        new CKA(CKA.CLASS, CKO.CERTIFICATE),
                        new CKA(CKA.CERTIFICATE_TYPE, CKC.CKC_X_509),
                        new CKA(CKA.TOKEN, true),
                        new CKA(CKA.LABEL, alias),
                        new CKA(CKA.SUBJECT, subject),
                        new CKA(CKA.ISSUER, cert.getIssuerX500Principal().getEncoded()),
                        new CKA(CKA.SERIAL_NUMBER, cert.getSerialNumber().toByteArray()),
                        new CKA(CKA.ID, alias),
                        new CKA(CKA.VALUE, cert.getEncoded())
                    };
                    long newCertRef = c.CreateObject(session, cert0Template);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Stored signer certificate object: " + newCertRef);
                    }
                    
                    while (iterator.hasNext()) {
                        cert = (X509Certificate) iterator.next();
                        subject = cert.getSubjectX500Principal().getEncoded();
                        
                        // Note: For now we assume CA certificate subject DN:s are unique
                        long[] existingRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.SUBJECT, subject));
                        
                        // Remove existing certificate that we will be replacing now
                        for (long existing : existingRefs) {
                            c.DestroyObject(session, existing);
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Destroyed certificate : " + existing + " for alias " + alias);
                            }
                        }

                        CKA[] certTemplate = new CKA[] {
                            new CKA(CKA.CLASS, CKO.CERTIFICATE),
                            new CKA(CKA.CERTIFICATE_TYPE, CKC.CKC_X_509),
                            new CKA(CKA.TOKEN, true),
                            new CKA(CKA.SUBJECT, subject),
                            new CKA(CKA.ISSUER, cert.getIssuerX500Principal().getEncoded()),
                            new CKA(CKA.SERIAL_NUMBER, cert.getSerialNumber().toByteArray()),
                            new CKA(CKA.VALUE, cert.getEncoded()),
                            new CKA(CKA.ID, getCertID(cert))
                        };
                        newCertRef = c.CreateObject(session, certTemplate);
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Stored CA certificate object: " + newCertRef);
                        }
                }
                    }
            } catch (CertificateEncodingException ex) {
                throw new IllegalArgumentException(ex);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        public Certificate getCertificate(String alias) { // TODO: Support for alias that are hexadecimal of label or Id
            Long session = null;
            try {
                session = aquireSession();

                // Search for all certificate objects on token
                long[] certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Certificate Objects: " +  Arrays.toString(certificateRefs));
                }

                if (certificateRefs.length < 1) {
                    throw new IllegalArgumentException("No such key");
                }
                
                CKA ckaValue = c.GetAttributeValue(session, certificateRefs[0], CKA.VALUE);
                CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
                Certificate cert = cf.generateCertificate(new ByteArrayInputStream(ckaValue.getValue()));
                return cert;
            } catch (CertificateEncodingException ex) {
                throw new IllegalArgumentException(ex);
            } catch (CertificateException | NoSuchProviderException ex) {
                throw new IllegalArgumentException(ex);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
        
        public List<Certificate> getCertificateChain(String alias) { // TODO: Support for finding aliases that are hexadecimal label or Id
            final LinkedList<Certificate> result = new LinkedList<>();
            Long session = null;
            try {
                session = aquireSession();

                // Search for all certificate objects on token
                long[] certificateRefs = findCertificateObjectsByLabel(session, alias);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Certificate Objects: " +  Arrays.toString(certificateRefs));
                }

                if (certificateRefs.length > 0) {
                    CKA ckaValue = getAttributeCertificateValue(session, certificateRefs[0]);
                    CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
                    Certificate cert = cf.generateCertificate(new ByteArrayInputStream(ckaValue.getValue()));
                    result.add(cert);
                    
                    X509Certificate xcert = (X509Certificate) cert;
                    // Don't continue if we found a self-signed cert
                    if (!xcert.getSubjectX500Principal().equals(xcert.getIssuerX500Principal())) {
                        certificateRefs = findCertificateObjectsBySubject(session, ((X509Certificate) cert).getIssuerX500Principal().getEncoded());
                        while (certificateRefs.length > 0) { // TODO: We might loop forever for incorrect subject/issuer attributes in a circle
                            ckaValue = getAttributeCertificateValue(session, certificateRefs[0]);
                            cert = cf.generateCertificate(new ByteArrayInputStream(ckaValue.getValue()));
                            result.add(cert);
                            xcert = (X509Certificate) cert;

                            // Don't continue if we found a self-signed cert
                            if (xcert.getSubjectX500Principal().equals(xcert.getIssuerX500Principal())) {
                                certificateRefs = new long[0];
                            } else {
                                certificateRefs = findCertificateObjectsBySubject(session, xcert.getIssuerX500Principal().getEncoded());
                            }
                        }
                    }
                }
                return result;
            } catch (CertificateEncodingException ex) {
                throw new IllegalArgumentException(ex);
            } catch (CertificateException | NoSuchProviderException ex) {
                throw new IllegalArgumentException(ex);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        private String toAlias(CKA ckaId, CKA ckaLabel) {
            final String result;
            // TODO: It could also happen that label or ID is not UTF-8 in which case we should use hex
            if (ckaLabel == null || ckaLabel.getValue() == null || ckaLabel.getValue().length == 0) {
                result = new String(ckaId.getValue(), StandardCharsets.UTF_8);
            } else {
                result = new String(ckaLabel.getValue(), StandardCharsets.UTF_8);
            }
            return result;
        }
        
        public Enumeration<SlotEntry> aliases() throws CryptoTokenOfflineException { // TODO: For now we just read all aliases but we should only read chunks and load the next one on demand to scale, see FindObjectsInit
            final LinkedList<SlotEntry> result = new LinkedList<>();            
            Long session = null;
            try {
                session = aquireSession();

                // 1. Search for all certificate objects on the token
                long[] certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Certificate Objects: " +  Arrays.toString(certificateRefs));
                }
                
                // Find those that have matching private keys
                for (long certRef : certificateRefs) {
                    CKA ckaId = c.GetAttributeValue(session, certRef, CKA.ID);
                    if (ckaId != null) {
                        long[] privRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.ID, ckaId.getValue()));
                        if (privRefs.length > 1) {
                            LOG.warn("More than one private key object sharing CKA_ID=0x" + Hex.toHexString(ckaId.getValue()));
                        } else if (privRefs.length == 1) {
                            CKA ckaLabel = c.GetAttributeValue(session, certRef, CKA.LABEL);                            
                            result.add(new SlotEntry(toAlias(ckaId, ckaLabel), TYPE_PRIVATEKEY_ENTRY));
                        }
                    }
                }

                long[] secretRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.SECRET_KEY));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Secret Objects: " + Arrays.toString(secretRefs));
                }

                for (long secretRef : secretRefs) {
                    CKA ckaId = c.GetAttributeValue(session, secretRef, CKA.ID);
                    if (ckaId != null) {
                        CKA ckaLabel = c.GetAttributeValue(session, secretRef, CKA.LABEL);
                        if (ckaLabel != null) {
                            result.add(new SlotEntry(toAlias(ckaId, ckaLabel), TYPE_SECRETKEY_ENTRY));
                        }
                    }
                }
                
                return new Enumeration<SlotEntry>() { // XXX
                    
                    int pos = 0;

                    @Override
                    public boolean hasMoreElements() {
                        return pos < result.size();
                    }

                    @Override
                    public SlotEntry nextElement() {
                        return result.get(pos++);
                    }
                };
            } catch (CKRException ex) {
                throw new CryptoTokenOfflineException(ex);
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

        // This method is currently private and can be reused later on to fetch value for particular attribute
        private CKA getAttribute(String alias, long cka) { // TODO: Support for alias that is hexadecimal of label or ID
            Long session = null;
            try {
                session = aquireSession();

                // Find certificate by label
                long[] certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Certificate Objects: " +  Arrays.toString(certificateRefs));
                }

                if (certificateRefs.length > 0) {
                    CKA ckaId = c.GetAttributeValue(session, certificateRefs[0], CKA.ID);
                    long[] privateObjects = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.ID, ckaId.getValue()));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Private Objects: " +  Arrays.toString(privateObjects));
                    }
                    if (privateObjects.length == 0) {
                        LOG.warn("No private key object with CKA_ID=0x" + Hex.toHexString(ckaId.getValue()));
                    } else if (privateObjects.length > 1) {
                        LOG.warn("More than one private key object sharing CKA_ID=0x" + Hex.toHexString(ckaId.getValue()));
                    } else {
                        return c.GetAttributeValue(session, privateObjects[0], cka);
                    }
                }
                return null;
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
        
        public CKA getAllowedMechanismAttribute(String alias, long cka) { // TODO: Support for alias that is hexadecimal of label or ID
            Long session = null;
            try {
                session = aquireSession();

                // Find certificate by label
                long[] certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Certificate Objects: " +  Arrays.toString(certificateRefs));
                }

                if (certificateRefs.length > 0) {
                    CKA ckaId = c.GetAttributeValue(session, certificateRefs[0], CKA.ID);
                    long[] privateObjects = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.ID, ckaId.getValue()));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Private Objects: " +  Arrays.toString(privateObjects));
                    }
                    if (privateObjects.length == 0) {
                        LOG.warn("No private key object with CKA_ID=0x" + Hex.toHexString(ckaId.getValue()));
                    } else if (privateObjects.length > 1) {
                        LOG.warn("More than one private key object sharing CKA_ID=0x" + Hex.toHexString(ckaId.getValue()));
                    } else {
                        return c.GetAttributeValue(session, privateObjects[0], cka);
                    }
                }
                return null;
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }
        
       /**
        * Same as CESeCoreUtils#securityInfo.
        *
        * @param alias
        * @param sb 
        */
        public void securityInfo(String alias, final StringBuilder sb) {
            Long session = null;
            try {
                session = aquireSession();

                // Find certificate by label
                long[] certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Certificate Objects: " +  Arrays.toString(certificateRefs));
                }

                if (certificateRefs.length > 0) {
                    CKA ckaId = c.GetAttributeValue(session, certificateRefs[0], CKA.ID);
                    long[] privateObjects = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.ID, ckaId.getValue()));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Private Objects: " +  Arrays.toString(privateObjects));
                    }
                    if (privateObjects.length == 0) {
                        sb.append("No private key object with CKA_ID=0x").append(Hex.toHexString(ckaId.getValue()));
                    } else if (privateObjects.length > 1) {
                        sb.append("More than one private key object sharing CKA_ID=0x").append(Hex.toHexString(ckaId.getValue()));
                    } else {
                        final CKA attrs[] = c.GetAttributeValue(session, privateObjects[0], 
                            CKA.SENSITIVE, 
                            CKA.ALWAYS_SENSITIVE,
                            CKA.EXTRACTABLE,
                            CKA.NEVER_EXTRACTABLE,
                            CKA.PRIVATE,
                            CKA.DERIVE,
                            CKA.MODIFIABLE);

                        for ( final CKA attr : attrs ) {
                            sb.append("  ");
                            sb.append(CKA.L2S(attr.type));
                            sb.append("=");
                            try {
                                sb.append(attr.getValueBool());
                            } catch (IllegalStateException ignored) { // NOPMD
                                sb.append("0x").append(Hex.toHexString(attr.getValue()));
                            }
                        }
                    }
                }
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
        }

//       public void securityInfo(final Key key, final StringBuilder sb) {
//           NJI11StaticSessionPrivateKey d = null;
//           if (key instanceof NJI11StaticSessionPrivateKey) {
//               d = (NJI11StaticSessionPrivateKey) key;
//           }
//           if (d == null) {
//               sb.append("Not a PKCS#11 key.");
//               return;
//           }
//           final CKA attrs[] = {
//                   new CKA(CKA.SENSITIVE),
//                   new CKA(CKA.ALWAYS_SENSITIVE),
//                   new CKA(CKA.EXTRACTABLE),
//                   new CKA(CKA.NEVER_EXTRACTABLE),
//                   new CKA(CKA.PRIVATE),
//                   new CKA(CKA.DERIVE),
//                   new CKA(CKA.MODIFIABLE)
//                   };
//           c.GetAttributeValue(d.getSession(), d.getObject(), attrs);
//           for ( final CKA attr : attrs ) {
//               sb.append("  ");
//               sb.append(attr.toString());
//           }
//        }

        /**
         * Note: format from SunPKCS11's P11KeyStore.
         * @param cert
         * @return 
         */
        private String getCertID(X509Certificate cert) {
            return cert.getSubjectX500Principal().getName(X500Principal.CANONICAL) +
                "/" +
                cert.getIssuerX500Principal().getName(X500Principal.CANONICAL) +
                "/" +
                cert.getSerialNumber().toString();
        }
        
        /**
        * fetches certificate objects with given label.
        *
        * @param session session in HSM slot used to fetch objects 
        * @param alias label of certificate
        * @return found certificate objects
        */
        long[] findCertificateObjectsByLabel(Long session, String alias) {
            long[] certificateRefs;
            
            if (useCache) {
                FindObjectsCallParamsHolder key = new FindObjectsCallParamsHolder(CKO_CERTIFICATE, CKA_LABEL, alias);
                if (cache.objectsExists(key)) {
                    certificateRefs = cache.getObjects(key);
                } else {
                    certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
                    // add search result to cache even if it is empty since this negative cached objects are cleared when key is generated
                    cache.addObjectsSearchResult(key, certificateRefs);
                }
            } else {
                certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.LABEL, alias));
            }
            
            return certificateRefs;
        }

        /**
        * fetches certificate objects with given subject.
        *
        * @param session session in HSM slot used to fetch objects 
        * @param ckaSubjectValue subject of certificate
        * @return found certificate objects
        */
        long[] findCertificateObjectsBySubject(Long session, byte[] ckaSubjectValue) {
            long[] certificateRefs;

            if (useCache) {
                FindObjectsCallParamsHolder key = new FindObjectsCallParamsHolder(CKO_CERTIFICATE, CKA_SUBJECT, null, ckaSubjectValue);
                if (cache.objectsExists(key)) {
                    certificateRefs = cache.getObjects(key);
                } else {
                    certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.SUBJECT, ckaSubjectValue));
                    cache.addObjectsSearchResult(key, certificateRefs);
                }
            } else {
                certificateRefs = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.CERTIFICATE), new CKA(CKA.SUBJECT, ckaSubjectValue));
            }

            return certificateRefs;
        }

        /**
        * fetches private key objects with given ID.
        *
        * @param session session in HSM slot used to fetch objects 
        * @param ckaIdValue ID of private key
        * @return found private key objects
        */
        long[] findPrivateKeyObjectsByID(Long session, byte[] ckaIdValue) {
            long[] privateObjects;
            if (useCache) {
                FindObjectsCallParamsHolder key = new FindObjectsCallParamsHolder(CKO_PRIVATE_KEY, CKA_ID, ckaIdValue, null);
                if (cache.objectsExists(key)) {
                    privateObjects = cache.getObjects(key);
                } else {
                    privateObjects = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.ID, ckaIdValue));
                    cache.addObjectsSearchResult(key, privateObjects);
                }
            } else {
                privateObjects = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.ID, ckaIdValue));
            }
            
            return privateObjects;
        }

        /**
         * Finds all private key objects (both token and session keys).
         * @return list of private key object handles
         */
        long[] findAllPrivateKeyObjects() {
            final long[] results;
            Long session = null;
            try {
                session = aquireSession();
                results = c.FindObjects(session, new CKA(CKA.CLASS, CKO.PRIVATE_KEY));
            } finally {
                if (session != null) {
                    releaseSession(session);
                }
            }
            return results;
        }

        /**
        * fetches secret key objects with given label.
        *
        * @param session session in HSM slot used to fetch objects 
        * @param alias label of secret key
        * @return found secret key objects
        */
        long[] findSecretKeyObjectsByLabel(Long session, String alias) {
            long[] secretObjects;
            if (useCache) {
                FindObjectsCallParamsHolder key = new FindObjectsCallParamsHolder(CKO_SECRET_KEY, CKA_LABEL, alias);
                if (cache.objectsExists(key)) {
                    secretObjects = cache.getObjects(key);
                } else {
                    secretObjects = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.SECRET_KEY), new CKA(CKA.LABEL, alias));
                    cache.addObjectsSearchResult(key, secretObjects);
                }
            } else {
                secretObjects = c.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.SECRET_KEY), new CKA(CKA.LABEL, alias));
            }

            return secretObjects;
        }
        
        /**
        * fetches ID of given certificate object.
        *
        * @param session session in HSM slot used to fetch attribute value 
        * @param certificateObject certificateObject
        * @return attribute value
        */
        CKA getAttributeCertificateID(long session, long certificateObject) {
            CKA ckaId;

            if (useCache) {
                GetAttributeValueCallParamsHolder key = new GetAttributeValueCallParamsHolder(certificateObject, CKA_ID);
                if (cache.attributeValueExists(key)) {
                    ckaId = cache.getAttributeValue(key);
                } else {
                    ckaId = c.GetAttributeValue(session, certificateObject, CKA.ID);
                    // Don't store in cache if ckaId or ckaId.getValue() is null
                    if (ckaId != null && ckaId.getValue() != null) {
                        cache.addAttributeValueSearchResult(key, ckaId);
                    }
                }
            } else {
                ckaId = c.GetAttributeValue(session, certificateObject, CKA.ID);
            }

            return ckaId;
        }

        /**
        * fetches VALUE of given certificate object.
        *
        * @param session session in HSM slot used to fetch attribute value 
        * @param certificateObject certificateObject
        * @return attribute value
        */
        CKA getAttributeCertificateValue(long session, long certificateObject) {
            CKA ckaValue;

            if (useCache) {
                GetAttributeValueCallParamsHolder key = new GetAttributeValueCallParamsHolder(certificateObject, CKA_VALUE);
                if (cache.attributeValueExists(key)) {
                    ckaValue = cache.getAttributeValue(key);
                } else {
                    ckaValue = c.GetAttributeValue(session, certificateObject, CKA.VALUE);
                    // Don't store in cache if ckaValue or ckaValue.getValue() is null
                    if (ckaValue != null && ckaValue.getValue() != null) {
                        cache.addAttributeValueSearchResult(key, ckaValue);
                    }
                }
            } else {
                ckaValue = c.GetAttributeValue(session, certificateObject, CKA.VALUE);
            }

            return ckaValue;
        }

        /**
        * fetches private key object in unwrapped form.
        *
        * @param session session in HSM slot used to fetch attribute value 
        * @param wrappingCipher cipher mechanism to be used for unwrapping the wrappedPrivateKey
        * @param unWrapKey secret key object used to unwrap wrapped private key
        * @param wrappedPrivateKey private key in wrapped form
        * @param unwrappedPrivateKeyTemplate unwrapped private key template
        * @return private key object
        */
        long getUnwrappedPrivateKey(long session, long wrappingCipher, long unWrapKey, byte[] wrappedPrivateKey, CKA[] unwrappedPrivateKeyTemplate) {
            long privateKey;

            CKM cipherMechanism = getCKMForWrappingCipher(wrappingCipher);

            if (LOG.isTraceEnabled()) {
                LOG.trace("c.UnwrapKey(" + session + ", " + cipherMechanism + ", " + unWrapKey + ", privLength:" + wrappedPrivateKey.length + ", templLength:" + unwrappedPrivateKeyTemplate.length);
            }
            try {
                privateKey = c.UnwrapKey(session, cipherMechanism, unWrapKey, wrappedPrivateKey, unwrappedPrivateKeyTemplate);
            } catch (CKRException ex) {
                // As there are sporadic failures with thie method returning 0x00000070: MECHANISM_INVALID, try again after a while:
                LOG.error("First error during c.unwrapKey call: " + ex.getMessage(), ex);
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ex1) {
                    LOG.error("Interrupted: " + ex1.getMessage(), ex1);
                }
                privateKey = c.UnwrapKey(session, cipherMechanism, unWrapKey, wrappedPrivateKey, unwrappedPrivateKeyTemplate);
                LOG.error("C.UnwrapKey call worked after first error");
            }

            // As there is 0x00000060: KEY_HANDLE_INVALID failure during engineInitSign, check if unwrapped private key 
            // actually exists. Try again if not.
            if (!unwrappedPrivateKeyExists(privateKey)) {
                LOG.error("Unwrapped private key does not exist actually, going to try again");
                privateKey = c.UnwrapKey(session, cipherMechanism, unWrapKey, wrappedPrivateKey, unwrappedPrivateKeyTemplate);
            }
            if (LOG.isTraceEnabled()) {
                LOG.trace("All private keys after c.UnwrapKey call: " + Arrays.toString(findAllPrivateKeyObjects()));
            }

            return privateKey;
        }

        void removeCertificateObject(long session, long certificateObject) {
            if (useCache) {
                cache.removeAllEntriesByObject(certificateObject);
            }
            c.DestroyObject(session, certificateObject);
        }
        
        void removeKeyObject(long session, long keyObject) {
            if (useCache) {
                cache.removeObjectsSearchResultByObject(keyObject);
            }
            c.DestroyObject(session, keyObject);
        }

        private CKM getCKMForWrappingCipher(long wrappingCipher) {
            CKM cipherMechanism = new CKM(wrappingCipher); // OK with nCipher
            // CKM cipherMechanism = new CKM(0x00001091); // SoftHSM2
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using mechanism: " + cipherMechanism);
            }
            return cipherMechanism;
        }
        
        private boolean unwrappedPrivateKeyExists(long unwrappedPrivateKey) {
            Long[] privateKeyObjectsBoxed = ArrayUtils.toObject(findAllPrivateKeyObjects());
            return Arrays.asList(privateKeyObjectsBoxed).contains(unwrappedPrivateKey);
        }

    }

    public JackNJI11Provider getProvider() {
        return provider;
    }
    
    public interface CertificateGenerator {
        X509Certificate generateCertificate(KeyPair keyPair, Provider provider) throws OperatorCreationException, CertificateException;
    }
}
