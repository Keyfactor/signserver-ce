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
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.KeyTestResult;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.SignServerException;
import org.signserver.server.KeyUsageCounterHash;

/**
 * Helper methods used by the CryptoTokens.
 *
 * @version $Id$
 */
public class CryptoTokenHelper {
    
    private static final Logger LOG = Logger.getLogger(CryptoTokenHelper.class);
   
    public static final String PROPERTY_NEXTCERTSIGNKEY = "NEXTCERTSIGNKEY";
    public static final String PROPERTY_ATTRIBUTESFILE = "ATTRIBUTESFILE";
    public static final String PROPERTY_ATTRIBUTES = "ATTRIBUTES";
    public static final String PROPERTY_SLOTLISTINDEX = "SLOTLISTINDEX";
    public static final String PROPERTY_SLOT = "SLOT";
    public static final String PROPERTY_SHAREDLIBRARY = "SHAREDLIBRARY";
    public static final String PROPERTY_PIN = "PIN";
    public static final String PROPERTY_DEFAULTKEY = "DEFAULTKEY";
    public static final String PROPERTY_AUTHCODE = "AUTHCODE";
    public static final String PROPERTY_SLOTLABELTYPE = "SLOTLABELTYPE";
    public static final String PROPERTY_SLOTLABELVALUE = "SLOTLABELVALUE";
    
    /** A workaround for the feature in SignServer 2.0 that property keys are 
     * always converted to upper case. The EJBCA CA Tokens usually use mixed case properties
     */
    public static Properties fixP11Properties(final Properties props) {
        String prop = props.getProperty(PROPERTY_AUTHCODE);
        if (prop != null) {
            props.setProperty("authCode", prop);
        }
        prop = props.getProperty(PROPERTY_DEFAULTKEY);
        if (prop != null) {
            props.setProperty("defaultKey", prop);
        }
        prop = props.getProperty(PROPERTY_PIN);
        if (prop != null) {
            props.setProperty("pin", prop);
        }
        prop = props.getProperty(PROPERTY_SHAREDLIBRARY);
        if (prop != null) {
            props.setProperty("sharedLibrary", prop);
        }
        prop = props.getProperty(PROPERTY_SLOTLABELVALUE);
        if (prop != null) {
            props.setProperty(org.cesecore.keys.token.PKCS11CryptoToken.SLOT_LABEL_VALUE, prop);
        }
        prop = props.getProperty(PROPERTY_SLOT);
        if (prop != null) {
            props.setProperty("slot", prop);
            props.setProperty(PROPERTY_SLOTLABELTYPE, Pkcs11SlotLabelType.SLOT_NUMBER.getKey());
            props.setProperty(org.cesecore.keys.token.PKCS11CryptoToken.SLOT_LABEL_VALUE, prop);
            props.setProperty(PROPERTY_SLOTLABELVALUE, prop);
        }
        prop = props.getProperty(PROPERTY_SLOTLISTINDEX);
        if (prop != null) {
            props.setProperty("slotListIndex", prop);
            props.setProperty(PROPERTY_SLOTLABELTYPE, Pkcs11SlotLabelType.SLOT_INDEX.getKey());
            props.setProperty(org.cesecore.keys.token.PKCS11CryptoToken.SLOT_LABEL_VALUE, prop);
            props.setProperty(PROPERTY_SLOTLABELVALUE, prop);
        }
        prop = props.getProperty(PROPERTY_ATTRIBUTESFILE);
        if (prop != null) {
            props.setProperty("attributesFile", prop);
        }
        prop = props.getProperty(PROPERTY_NEXTCERTSIGNKEY);
        if (prop != null) {
            props.setProperty("nextCertSignKey", prop);
        }
        prop = props.getProperty(PROPERTY_SLOTLABELTYPE);
        if (prop != null) {
            props.setProperty(org.cesecore.keys.token.PKCS11CryptoToken.SLOT_LABEL_TYPE, prop);
        }
        return props;
    }
    
    /**
     * Remove a key with the specified alias from the keystore.
     * @param keyStore to remove from
     * @param alias of key to remove
     * @return true if the key alias was removed
     * @throws CryptoTokenOfflineException if the keystore was null
     * @throws KeyStoreException for keystore related errors
     * @throws SignServerException if the keystore did not contain a key with the specified alias
     */
    public static boolean removeKey(final KeyStore keyStore, final String alias) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
        if (keyStore == null) {
            throw new CryptoTokenOfflineException("Token offline");
        }
        if (!keyStore.containsAlias(alias)) {
            throw new SignServerException("No such alias in token: " + alias);
        }
        keyStore.deleteEntry(alias);
        return !keyStore.containsAlias(alias);
    }

    /**
     * Performs test signatures for the specified keys or for all if "all" specified.
     * @param keyStore Loaded keystore to read keys from
     * @param alias Alias of key to test or "all" to test all
     * @param authCode Key password (if used, ie for JKS only)
     * @param signatureProvider Provider for creating the signature
     * @return The results for each key found
     * @throws CryptoTokenOfflineException In case the key could not be used
     */
    public static Collection<KeyTestResult> testKey(KeyStore keyStore, String alias, char[] authCode, String signatureProvider) throws CryptoTokenOfflineException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("testKey for alias: " + alias);
        }

        final Collection<KeyTestResult> result = new LinkedList<KeyTestResult>();

        try {
            final Enumeration<String> e = keyStore.aliases();
            while (e.hasMoreElements()) {
                final String keyAlias = e.nextElement();
                if (alias.equalsIgnoreCase(ICryptoToken.ALL_KEYS)
                        || alias.equals(keyAlias)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("checking keyAlias: " + keyAlias);
                    }

                    if (keyStore.isKeyEntry(keyAlias)) {
                        String status;
                        String publicKeyHash = null;
                        boolean success = false;
                        try {
                            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, authCode);
                            final Certificate entryCert = keyStore.getCertificate(keyAlias);
                            if (entryCert != null) {
                                final PublicKey publicKey = entryCert.getPublicKey();
                                publicKeyHash = createKeyHash(publicKey);
                                testSignAndVerify(privateKey, publicKey, signatureProvider);
                                success = true;
                                status = "";
                            } else {
                                status = "Not testing keys with alias "
                                        + keyAlias + ". No certificate exists.";
                            }
                        } catch (ClassCastException ce) {
                            status = "Not testing keys with alias "
                                    + keyAlias + ". Not a private key.";
                        } catch (InvalidKeyException ex) {
                            LOG.error("Error testing key: " + keyAlias, ex);
                            status = ex.getMessage();
                        } catch (KeyStoreException ex) {
                            LOG.error("Error testing key: " + keyAlias, ex);
                            status = ex.getMessage();
                        } catch (NoSuchAlgorithmException ex) {
                            LOG.error("Error testing key: " + keyAlias, ex);
                            status = ex.getMessage();
                        } catch (NoSuchProviderException ex) {
                            LOG.error("Error testing key: " + keyAlias, ex);
                            status = ex.getMessage();
                        } catch (SignatureException ex) {
                            LOG.error("Error testing key: " + keyAlias, ex);
                            status = ex.getMessage();
                        } catch (UnrecoverableKeyException ex) {
                            LOG.error("Error testing key: " + keyAlias, ex);
                            status = ex.getMessage();
                        }
                        result.add(new KeyTestResult(keyAlias, success, status,
                                publicKeyHash));
                    }
                }
            }
        } catch (KeyStoreException ex) {
            throw new CryptoTokenOfflineException(ex);
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("<testKey");
        }
        return result;
    }

    /**
     * Creates a test signature and verifies it.
     *
     * @param privateKey Private key to sign with
     * @param publicKey Public key to verify with
     * @param signatureProvider Name of provider to sign with
     * @throws NoSuchAlgorithmException In case the key or signature algorithm is unknown
     * @throws NoSuchProviderException In case the supplied provider name is unknown or BC is not installed
     * @throws InvalidKeyException If signature verification failed or the key was invalid
     * @throws SignatureException If the signature could not be made or verified correctly
     */
    public static void testSignAndVerify(PrivateKey privateKey, PublicKey publicKey, String signatureProvider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        final byte input[] = "Lillan gick pa vagen ut, motte dar en katt...".getBytes();
        final String sigAlg = suggestSigAlg(publicKey);
        if (sigAlg == null) {
            throw new NoSuchAlgorithmException("Unknown key algorithm: "
                    + publicKey.getAlgorithm());
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Testing keys with algorithm: " + publicKey.getAlgorithm());
            LOG.debug("testSigAlg: " + sigAlg);
            LOG.debug("provider: " + signatureProvider);
            LOG.trace("privateKey: " + privateKey);
            LOG.trace("privateKey class: " + privateKey.getClass().getName());
            LOG.trace("publicKey: " + publicKey);
            LOG.trace("publicKey class: " + publicKey.getClass().getName());
        }
        final Signature signSignature = Signature.getInstance(sigAlg, signatureProvider);
        signSignature.initSign(privateKey);
        signSignature.update(input);
        byte[] signBA = signSignature.sign();
        if (LOG.isDebugEnabled()) {
            if (signBA != null) {
                LOG.trace("Created signature of size: " + signBA.length);
                LOG.trace("Created signature: " + new String(Hex.encode(signBA)));
            } else {
                LOG.warn("Test signature is null?");
            }
        }

        final Signature verifySignature = Signature.getInstance(sigAlg, "BC");
        verifySignature.initVerify(publicKey);
        verifySignature.update(input);
        if (!verifySignature.verify(signBA)) {
            throw new InvalidKeyException("Test signature inconsistent");
        }
    }

    /**
     * Generate a certificate signing request (PKCS#10).
     * @param info A PKCS10CertReqInfo
     * @param privateKey Private key for signing the request
     * @param signatureProvider Name of provider to sign with
     * @param publicKey Public key to include in the request
     * @param explicitEccParameters True if the EC domain parameters should be included (ie. not a named curve)
     * @return the certificate request data
     */
    public static ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            final PrivateKey privateKey, final String signatureProvider, PublicKey publicKey,
            final boolean explicitEccParameters) throws IllegalArgumentException {
        LOG.debug(">genCertificateRequest");
        final Base64SignerCertReqData retval;
        if (info instanceof PKCS10CertReqInfo) {
            PKCS10CertReqInfo reqInfo = (PKCS10CertReqInfo) info;
            org.bouncycastle.pkcs.PKCS10CertificationRequest pkcs10;

            if (LOG.isDebugEnabled()) {
                LOG.debug("signatureAlgorithm: "
                        + reqInfo.getSignatureAlgorithm());
                LOG.debug("subjectDN: " + reqInfo.getSubjectDN());
                LOG.debug("explicitEccParameters: " + explicitEccParameters);
            }

            try {
                // Handle ECDSA key with explicit parameters
                if (explicitEccParameters
                        && publicKey.getAlgorithm().contains("EC")) {
                    publicKey = ECKeyUtil.publicToExplicitParameters(publicKey,
                            "BC");
                }

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Public key SHA1: " + createKeyHash(
                            publicKey));
                    LOG.debug("Public key SHA256: "
                            + KeyUsageCounterHash.create(publicKey));
                }

                // Generate request
                final JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(CertTools.stringToBCDNString(reqInfo.getSubjectDN())), publicKey);
                final ContentSigner contentSigner = new JcaContentSignerBuilder(reqInfo.getSignatureAlgorithm()).setProvider(signatureProvider).build(privateKey);
                pkcs10 = builder.build(contentSigner);
                retval = new Base64SignerCertReqData(Base64.encode(pkcs10.getEncoded()));
            } catch (IOException e) {
                throw new IllegalArgumentException("Certificate request error: " + e.getMessage(), e);
            } catch (OperatorCreationException e) {
                throw new IllegalArgumentException("Certificate request error: " + e.getMessage(), e);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalArgumentException("Certificate request error: " + e.getMessage(), e);
            } catch (NoSuchProviderException e) {
                throw new IllegalArgumentException("Certificate request error: " + e.getMessage(), e);
            }
            LOG.debug("<genCertificateRequest");
            return retval;
        } else {
            throw new IllegalArgumentException("Unsupported certificate request info type: " + info.getClass().getName());
        }
    }

    /**
     * Creates a SHA-1 hash for the public key.
     * @param key to create hash for
     * @return Hex encoded hash
     */
    public static String createKeyHash(PublicKey key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1", "BC");
            final String res = new String(Hex.encode(md.digest(key.getEncoded())));
            md.reset();
            return res;
        } catch (NoSuchProviderException ex) {
            final String message = "Nu such provider trying to hash public key";
            LOG.error(message, ex);
            throw new RuntimeException(message, ex);
        } catch (NoSuchAlgorithmException ex) {
            final String message = "Nu such algorithm trying to hash public key";
            LOG.error(message, ex);
            throw new RuntimeException(message, ex);
        }
    }

    /**
     * Suggests a signature algorithm base on public key type.
     * @param key public key
     * @return One signature algorithm that should work with the key type
     */
    public static String suggestSigAlg(PublicKey key) {
        final String alg;
        if (key instanceof ECKey) {
            alg = "SHA1withECDSA";
        } else if (key instanceof RSAKey) {
            alg = "SHA1withRSA";
        } else if (key instanceof DSAKey) {
            alg = "SHA1withDSA";
        } else {
            alg = null;
        }
        return alg;
    }
}
