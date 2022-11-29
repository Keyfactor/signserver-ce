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
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.PredicateUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.util.CertTools;
import org.cesecore.util.QueryParameterException;
import org.cesecore.util.query.Elem;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.clauses.Order;
import org.cesecore.util.query.elems.LogicOperator;
import org.cesecore.util.query.elems.Operation;
import org.cesecore.util.query.elems.Term;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.KeyTestResult;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.Pkcs10CertReqData;
import org.signserver.common.QueryException;
import org.signserver.common.SignServerConstants;
import org.signserver.common.SignServerException;
import org.signserver.server.IServices;
import org.signserver.server.KeyUsageCounterHash;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounter;
import static org.signserver.common.SignServerConstants.TOKEN_ENTRY_FIELDS_ALIAS;
import static org.signserver.common.SignServerConstants.TOKEN_ENTRY_FIELDS_KEY_ALIAS;

/**
 * Helper methods used by the CryptoTokens.
 *
 * @version $Id$
 */
public class CryptoTokenHelper {
    
    private static final Logger LOG = Logger.getLogger(CryptoTokenHelper.class);

    public static final String PROPERTY_CRYPTOTOKEN = "CRYPTOTOKEN";
    public static final String PROPERTY_NEXTCERTSIGNKEY = "NEXTCERTSIGNKEY";
    public static final String PROPERTY_ATTRIBUTESFILE = "ATTRIBUTESFILE";
    public static final String PROPERTY_ATTRIBUTES = "ATTRIBUTES";
    public static final String PROPERTY_SLOTLISTINDEX = "SLOTLISTINDEX";
    public static final String PROPERTY_SLOT = "SLOT";
    public static final String PROPERTY_SHAREDLIBRARY = "SHAREDLIBRARY";
    public static final String PROPERTY_SHAREDLIBRARYNAME = "SHAREDLIBRARYNAME";
    public static final String PROPERTY_PIN = "PIN";
    public static final String PROPERTY_DEFAULTKEY = "DEFAULTKEY";
    public static final String PROPERTY_AUTHCODE = "AUTHCODE";
    public static final String PROPERTY_SLOTLABELTYPE = "SLOTLABELTYPE";
    public static final String PROPERTY_SLOTLABELVALUE = "SLOTLABELVALUE";
    
    public static final String PROPERTY_KEYGENERATIONLIMIT = "KEYGENERATIONLIMIT";
    
    public static final String PROPERTY_SELFSIGNED_DN = "SELFSIGNED_DN";
    public static final String PROPERTY_SELFSIGNED_VALIDITY = "SELFSIGNED_VALIDITY";
    public static final String PROPERTY_SELFSIGNED_SIGNATUREALGORITHM = "SELFSIGNED_SIGNATUREALGORITHM";
    public static final String PROPERTY_GENERATE_CERTIFICATE_OBJECT = "GENERATE_CERTIFICATE_OBJECT";

    public static final String INFO_KEY_SPECIFICATION = "Key specification";
    public static final String INFO_KEY_ALGORITHM = "Key algorithm";
    public static final String INFO_KEY_PUBLIC_EXPONENT = "Public exponent";
    public static final String INFO_KEY_SIGNINGS = "Signings";
    public static final String INFO_KEY_WRAPPING_KEY = "Wrapping Key";
    public static final String INFO_KEY_WRAPPING_CIPHER = "Wrapping Cipher";
    
    public static final String INFO_KEY_MODIFIABLE = "Modifiable";
    public static final String INFO_KEY_PKCS11_ATTRIBUTES = "PKCS#11 Attributes";
    public static final String INFO_KEY_ALLOWED_MECHANISMS = "Allowed Mechanisms";

    public static final String PROPERTY_ALLOWED_MECHANISMS = "ALLOWED_MECHANISMS";
    
    public static final String SECRET_KEY_PREFIX = "SEC:";
    public static final String CKM_SECRET_KEY_ALGO_SUFFIX = "_KEY_GEN";
    public static final String CKM_PREFIX = "CKM_";
    public static final String PROPERTY_WRAPPING_CIPHER_ALGORITHM = "WRAPPING_CIPHER_ALGORITHM";
    public static final String DEFAULT_WRAPPING_CIPHER_ALGORITHM = "CKM_AES_CBC_PAD";
    
    private static final long DEFAULT_BACKDATE = (long) 10 * 60; // 10 minutes in seconds
    private static final long DEFAULT_VALIDITY_S = (long) 30 * 24 * 60 * 60 * 365; // 30 year in seconds
    private static final String DEFAULT_SIGNATUREALGORITHM = "SHA1withRSA"; // Legacy default

    public static final String PROPERTY_USE_CACHE = "USE_CACHE";
    public static final String DEFAULT_PROPERTY_USE_CACHE = "TRUE";
 
    // properties for Azure Key Vault
    public static final String PROPERTY_KEY_VAULT_NAME = "KEY_VAULT_NAME";
    public static final String PROPERTY_KEY_VAULT_TYPE = "KEY_VAULT_TYPE";
    public static final String PROPERTY_KEY_VAULT_CLIENT_ID = "KEY_VAULT_CLIENT_ID";

    public enum TokenEntryFields {
        /** Key alias of entry. */
        keyAlias,
        
        /**
         * Type of entry.
         * @see TokenEntry#TYPE_PRIVATEKEY_ENTRY
         * @see TokenEntry#TYPE_SECRETKEY_ENTRY
         * @see TokenEntry#TYPE_TRUSTED_ENTRY
         */
        type,
        
    }
    
    /** DN part used to mark dummy certificates by SignServer. */
    private static final String SUBJECT_DUMMY = "L=_SignServer_DUMMY_CERT_";
    private static final String CESECORE_SUBJECT_DUMMY_CN = "CN=some guy";
    private static final String CESECORE_SUBJECT_DUMMY_L = "L=around";
    private static final String CESECORE_SUBJECT_DUMMY_C = "C=US";
    private static final String CESECORE_SUBJECT_DN_6_8 = "CN=Dummy certificate created by a CESeCore application"; // Since ~6.8.0
    public static final String SUBJECT_DUMMY_4_3_0 = "CN=Dummy cert for ";
    
    private static final String[] KNOWNSECRETKEYALGONAMES = {
        "AES",
        "DES"};
    private static final String SECRET_KEY_ALGO_DESede = "DESede";
    private static final String SECRET_KEY_ALGO_Triple_DES = "DES3";
        
    /**
     * A workaround for the feature in SignServer 2.0 that property keys are 
     * always converted to upper case. The EJBCA CA Tokens usually use mixed case properties.
     * 
     * @param props Properties
     * @return Properties with keys case-converted
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
        prop = props.getProperty(PROPERTY_SHAREDLIBRARYNAME);
        if (prop != null) {
            props.setProperty("sharedLibraryName", prop);
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

    // TODO: some duplication from fixP11Properties
    public static Properties fixAzureKeyVaultProperties(final Properties props) {
        String prop = props.getProperty(PROPERTY_KEY_VAULT_NAME);
        if (prop != null) {
            props.setProperty("keyVaultName", prop);
        }

        prop = props.getProperty(PROPERTY_KEY_VAULT_TYPE);
        if (prop != null) {
            props.setProperty("keyVaultType", prop);
        }

        prop = props.getProperty(PROPERTY_KEY_VAULT_CLIENT_ID);
        if (prop != null) {
            props.setProperty("keyVaultClientID", prop);
        }

        prop = props.getProperty(PROPERTY_PIN);
        if (prop != null) {
            props.setProperty("pin", prop);
        }

        prop = props.getProperty(PROPERTY_DEFAULTKEY);
        if (prop != null) {
            props.setProperty("defaultKey", prop);
        }

        prop = props.getProperty(PROPERTY_NEXTCERTSIGNKEY);
        if (prop != null) {
            props.setProperty("nextCertSignKey", prop);
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
    public static boolean removeKey(final KeyStoreDelegator keyStore, final String alias) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
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
     * @param signatureAlgorithm To test signing with or null to use the default
     * @return The results for each key found
     * @throws CryptoTokenOfflineException In case the key could not be used
     */
    public static Collection<KeyTestResult> testKey(KeyStoreDelegator keyStore, String alias, char[] authCode, String signatureProvider, String signatureAlgorithm) throws CryptoTokenOfflineException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("testKey for alias: " + alias);
        }

        final Collection<KeyTestResult> result = new LinkedList<>();

        try {
            if (alias.equalsIgnoreCase(ICryptoTokenV4.ALL_KEYS)) {
            
                for (final TokenEntry entry : keyStore.getEntries()) {
                    final String keyAlias = entry.getAlias();

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("checking keyAlias: " + keyAlias);
                    }

                    if (TokenEntry.TYPE_SECRETKEY_ENTRY.equals(entry.getType())) {
                        result.add(new KeyTestResult(keyAlias, false, "Not testing keys with alias: " + keyAlias + ". Not a private key.", null));
                    } else if (TokenEntry.TYPE_PRIVATEKEY_ENTRY.equals(entry.getType())) {
                        result.add(testPrivateKey(keyStore, keyAlias, authCode, signatureProvider, signatureAlgorithm));
                    } else {
                        result.add(new KeyTestResult(keyAlias, false, "No such key: " + keyAlias, null));
                    }
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("checking keyAlias: " + alias);
                }
                if (!keyStore.containsAlias(alias)) {
                    result.add(new KeyTestResult(alias, false, "No such key: " + alias, null));
                } else {
                    result.add(testPrivateKey(keyStore, alias, authCode, signatureProvider, signatureAlgorithm));
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
    
    private static KeyTestResult testPrivateKey(KeyStoreDelegator keyStore, String keyAlias, char[] authCode, String signatureProvider, String signatureAlgorithm) throws CryptoTokenOfflineException {
        boolean success = false;
        String publicKeyHash = null;
        String status;
        PrivateKey privateKey = null;
        try {
            privateKey = keyStore.aquirePrivateKey(keyAlias, authCode);
            final PublicKey publicKey = keyStore.getPublicKey(keyAlias);
            if (publicKey != null) {
                publicKeyHash = createKeyHash(publicKey);
                testSignAndVerify(privateKey, publicKey, signatureProvider, signatureAlgorithm);
                success = true;
                status = "";
            } else {
                status = "Not testing keys with alias "
                        + keyAlias + ". No public key exists.";
            }
        } catch (ClassCastException ce) {
            status = "Not testing keys with alias "
                    + keyAlias + ". Not a private key.";
        } catch (InvalidKeyException | KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | UnrecoverableKeyException | OperatorCreationException | IOException ex) {
            LOG.error("Error testing key: " + keyAlias, ex);
            status = ex.getMessage();
        } finally {
            if (privateKey != null) {
                keyStore.releasePrivateKey(privateKey);
            }
        }
        
        return new KeyTestResult(keyAlias, success, status, publicKeyHash);
    }

    /**
     * Creates a test signature and verifies it.
     *
     * @param privateKey Private key to sign with
     * @param publicKey Public key to verify with
     * @param signatureProvider Name of provider to sign with
     * @param signatureAlgorithm To use for the test signature or null to use the default
     * @throws NoSuchAlgorithmException In case the key or signature algorithm is unknown
     * @throws NoSuchProviderException In case the supplied provider name is unknown or BC is not installed
     * @throws InvalidKeyException If signature verification failed or the key was invalid
     * @throws SignatureException If the signature could not be made or verified correctly
     */
    public static void testSignAndVerify(PrivateKey privateKey, PublicKey publicKey, String signatureProvider, String signatureAlgorithm) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, OperatorCreationException, IOException {
        final byte input[] = "Lillan gick pa vagen ut, motte dar en katt...".getBytes();
        final String sigAlg;
        if (signatureAlgorithm == null) {
            sigAlg = suggestSigAlg(publicKey);
        } else {
            sigAlg = signatureAlgorithm;
        }
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
        final JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(sigAlg);
        signerBuilder.setProvider(signatureProvider);
        final ContentSigner signer = new BufferingContentSigner(signerBuilder.build(privateKey));
        try (OutputStream signerOut = signer.getOutputStream()) {
            signerOut.write(input);
        }
        final byte[] signBA = signer.getSignature();
        if (LOG.isTraceEnabled()) {
            LOG.trace("Created signature of size: " + signBA.length);
            LOG.trace("Created signature: " + new String(Hex.encode(signBA)));
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
        final Pkcs10CertReqData retval;
        if (info instanceof PKCS10CertReqInfo) {
            PKCS10CertReqInfo reqInfo = (PKCS10CertReqInfo) info;
            PKCS10CertificationRequest pkcs10;

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
                final JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(CertTools.stringToBcX500Name(reqInfo.getSubjectDN()), publicKey);
                final ContentSigner contentSigner = new JcaContentSignerBuilder(reqInfo.getSignatureAlgorithm()).setProvider(signatureProvider).build(privateKey);
                pkcs10 = builder.build(contentSigner);
                retval = new Pkcs10CertReqData(pkcs10);
            } catch (IOException | OperatorCreationException | NoSuchAlgorithmException | NoSuchProviderException e) {
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
            return res;
        } catch (NoSuchProviderException ex) {
            final String message = "No such provider trying to hash public key";
            LOG.error(message, ex);
            throw new RuntimeException(message, ex);
        } catch (NoSuchAlgorithmException ex) {
            final String message = "No such algorithm trying to hash public key";
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
        String alg = null;
        if (key != null) {
            switch (key.getAlgorithm()) {
                case "EC":
                case "ECDSA":
                    alg = "SHA256withECDSA";
                    break;
                case "RSA":
                    alg = "SHA256withRSA";
                    break;
                case "DSA":
                    alg = "SHA256withDSA";
                    break;
                case "Ed25519":
                    alg = "Ed25519";
                    break;
                case "Ed448":
                    alg = "Ed448";
                    break;
                case "ED":
                case "Ed":
                case "EDDSA":
                case "EdDSA":
                    alg = "Ed25519";
                    break;
            }
            if (alg == null) {
                if (key instanceof ECKey) {
                    alg = "SHA256withECDSA";
                } else if (key instanceof RSAKey) {
                    alg = "SHA256withRSA";
                } else if (key instanceof DSAKey) {
                    alg = "SHA256withDSA";
                } else {
                    alg = null;
                }
            }
        }
        return alg;
    }

    /**
     * Checks if the certificate looks like one of those dummy certificates
     * generated by either SignServer or CESeCore.
     * @param certificate to check
     * @return True if the certificate looks like a dummy certificate
     */
    public static boolean isDummyCertificate(Certificate certificate) {
        final boolean result;
        if (certificate instanceof X509Certificate) {
            result = isDummyCertificateDN(((X509Certificate) certificate).getSubjectX500Principal().getName());
        } else {
            result = false;
        }
        return result;
    }
    
    /**
     * Checks if the DN looks like one from a dummy certificate
     * generated by either SignServer or CESeCore.
     * @param dn to check
     * @return True if the certificate looks like a dummy certificate DN
     */
    public static boolean isDummyCertificateDN(final String dn) {
        return dn.contains(SUBJECT_DUMMY)
                || (dn.contains(CESECORE_SUBJECT_DN_6_8))
                || (dn.contains(CESECORE_SUBJECT_DUMMY_CN) && dn.contains(CESECORE_SUBJECT_DUMMY_L) && dn.contains(CESECORE_SUBJECT_DUMMY_C))
                || dn.contains(SUBJECT_DUMMY_4_3_0);
    }
    
    /**
     * Creates a self-signed dummy certificate that can be used as place holder
     * in a keystore and is recognized as a dummy certificate by a call to
     * isDummyCertificate().
     * @param commonName to use as CN
     * @param sigAlgName signature algorithm for the certificate
     * @param keyPair with public key to include and private key to sign with 
     * @param provider to use for signing
     * @return the new certificate
     * @throws OperatorCreationException
     * @throws CertificateException 
     * @see #isDummyCertificate(java.security.cert.Certificate)
     */
    public static X509Certificate createDummyCertificate(String commonName, String sigAlgName, KeyPair keyPair, String provider) throws OperatorCreationException, CertificateException {
        return getSelfCertificate(getDummyCertificateDN(commonName), DEFAULT_BACKDATE, DEFAULT_VALIDITY_S, sigAlgName, keyPair, provider);
    }
    
    private static String getDummyCertificateDN(String commonName) {
        return "CN=" + commonName + ", " + SUBJECT_DUMMY + ", C=SE";
    }
    
    private static X509Certificate getSelfCertificate (String myname,
                                                long backdate,
                                                long validity,
                                                String sigAlg,
                                                KeyPair keyPair,
                                                String provider) throws OperatorCreationException, CertificateException {
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime - backdate * 1000);
        final Date lastDate = new Date(currentTime + validity * 1000);

        // Add all mandatory attributes
        if (LOG.isDebugEnabled()) {
            LOG.debug("keystore signing algorithm " + sigAlg);
        }

        final PublicKey publicKey = keyPair.getPublic();
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key is null");
        }

        X509v3CertificateBuilder cg = new JcaX509v3CertificateBuilder(new X500Principal(myname), BigInteger.valueOf(firstDate.getTime()), firstDate, lastDate, new X500Principal(myname), publicKey);
        final JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(sigAlg);
        contentSignerBuilder.setProvider(provider);

        final ContentSigner contentSigner = contentSignerBuilder.build(keyPair.getPrivate());

        return new JcaX509CertificateConverter().getCertificate(cg.build(new BufferingContentSigner(contentSigner)));
    }

    public static TokenSearchResults searchTokenEntries(final KeyStoreDelegator keyStore, final int startIndex, final int max, final QueryCriteria qc, final boolean includeData, IServices services, char[] authCode) throws CryptoTokenOfflineException, QueryException {
        final TokenSearchResults result;
        try {
            final ArrayList<TokenEntry> tokenEntries = new ArrayList<>();

            final List<TokenEntry> entries = keyStore.getEntries();
            final List<TokenEntry> filteredEntries = new LinkedList<>();
            
            for (final TokenEntry entry : entries) {
                if (shouldBeIncluded(entry, qc)) {
                    filteredEntries.add(entry);
                }
            }
            
            // apply ordering if applicable
            handleOrdering(filteredEntries, qc);
            
            final long maxIndex = (long) startIndex + max;
            
            for (int i = startIndex; i < maxIndex && i < filteredEntries.size(); i++) {
                final TokenEntry entry = filteredEntries.get(i);
                final String keyAlias = entry.getAlias();
             
                if (LOG.isDebugEnabled()) {
                    LOG.debug("checking keyAlias: " + keyAlias);
                }

                // Add additional data

                if (includeData) {
                    keyStore.addAdditionalDataToEntry(entry, authCode, services);
                }
                tokenEntries.add(entry);
            }

            result = new TokenSearchResults(tokenEntries, filteredEntries.size() > maxIndex);
        } catch (KeyStoreException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
        return result;
    }
    
    private static boolean shouldBeIncluded(TokenEntry tokenEntry, QueryCriteria qc) throws QueryException {
        final List<Elem> terms = new ArrayList<>();
            
        CollectionUtils.selectRejected(qc.getElements(), PredicateUtils.instanceofPredicate(Order.class), terms);
        if (terms.isEmpty()) {
            return true;
        }
        return generate(tokenEntry, terms.iterator().next());
    }
    
    private static boolean generate(TokenEntry tokenEntry, final Elem elem) throws QueryException {
        if (elem instanceof Operation) {
            return generateRestriction(tokenEntry, (Operation) elem);
        } else if (elem instanceof Term) {
            return matches(tokenEntry, (Term) elem);
        } else {
            throw new QueryParameterException("No matched restriction");
        }
    }
    
    private static boolean generateRestriction(TokenEntry tokenEntry, final Operation op) throws QueryException {
        boolean left = matches(tokenEntry, op.getTerm());
        final Elem elem = op.getElement();
        
        if (op.getOperator() == LogicOperator.OR && left) {
            return true;
        } else if (op.getOperator() == LogicOperator.AND && !left) {
            return false;
        } else if (elem == null) {
            return left;
        } else {
            return generate(tokenEntry, elem);
        }
    }
    
    private static boolean matches(TokenEntry entry, Term term) throws QueryException {
        final boolean result;
        
        final Object actualValue;
        switch (TokenEntryFields.valueOf(term.getName())) {
            case keyAlias: {
                actualValue = entry.getAlias();
                break;
            }
            default: {
                throw new QueryException("Unsupported token entry field in query terms: " + term.getName());
            }
        }
        switch (term.getOperator()) {
            case EQ: {
                result = term.getValue().equals(actualValue);
                break;
            }
            case NEQ: {
                result = !term.getValue().equals(actualValue);
                break;
            }
            case NULL: {
                result = term.getValue() == null;
                break;
            }
            case NOTNULL: {
                result = term.getValue() != null;
                break;
            }
            case LIKE: {
                if (term.getValue() instanceof String && actualValue != null) {
                    final String value = (String) term.getValue();
                    // TODO: At the moment we only support '%' and only in beginning and/or end of value
                    final boolean wildcardInBeginning = value.startsWith("%");
                    final boolean wildcardAtEnd = value.endsWith("%");
                    
                    if (!wildcardInBeginning && !wildcardAtEnd) {
                        result = value.equals(actualValue);
                    } else {
                        final String content = value.substring(wildcardInBeginning ? 1 : 0, wildcardAtEnd ? value.length() - 1 : value.length());
                        if (wildcardInBeginning && wildcardAtEnd) {
                            result = actualValue.toString().contains(content);
                        } else if (wildcardInBeginning) {
                            result = actualValue.toString().endsWith(content);
                        } else {
                            result = actualValue.toString().startsWith(content);
                        }
                    }
                } else {
                    result = false;
                }
                break;
            }
            default: {
                throw new QueryException("Operator not yet supported in query terms: " + term.getOperator().name());
            }
        }
        
        return result;
    }
    
    /**
     * Checks that the supplied certificate has a public key matching the
     * exiting one in the keystore.
     * @param keyStore to get the current public key from
     * @param alias of the entry to check
     * @param newCertificate to compare with the current one
     * @throws KeyStoreException if the keystore has not been initialized
     * @throws CryptoTokenOfflineException in case the keys does not match
     */
    public static void ensureNewPublicKeyMatchesOld(KeyStoreDelegator keyStore, String alias, Certificate newCertificate) throws KeyStoreException, CryptoTokenOfflineException {
        PublicKey oldPublicKey = keyStore.getPublicKey(alias);
        if (!oldPublicKey.equals(newCertificate.getPublicKey())) {
            throw new CryptoTokenOfflineException("New certificate public key does not match current one");
        }
    }
    
    /**
     * Get an AlgorithmParameterSpec for RSA given a key specification given
     * a string of the form "<key length> exp <decimal>" or
     * "<key length> exp 0x<hexadecimal>.
     * 
     * Examples: "2048 exp 65537", "2048 exp 0x10001"
     * 
     * The spaces surrounding "exp" are optional.
     * 
     * @param keySpec
     * @return
     * @throws InvalidAlgorithmParameterException 
     */
    public static RSAKeyGenParameterSpec getPublicExponentParamSpecForRSA(final String keySpec)
        throws InvalidAlgorithmParameterException {
        final String[] parts = keySpec.split("exp");

        if (parts.length != 2) {
            throw new InvalidAlgorithmParameterException("Invalid specification of public exponent");
        }

        final int keyLength;
        try {
            keyLength = Integer.parseInt(parts[0].trim());
        } catch (NumberFormatException ex) {
            throw new InvalidAlgorithmParameterException("Invalid key length " + ex.getMessage(), ex);
        }

        final String exponentString = parts[1].trim();
        final BigInteger exponent;
        try {
            if (exponentString.startsWith("0x")) {
                exponent = new BigInteger(exponentString.substring(2), 16);
            } else {
                exponent = new BigInteger(exponentString);
            }
        } catch (NumberFormatException ex) {
            throw new InvalidAlgorithmParameterException("Invalid exponent " + ex.getMessage(), ex);
        }

        return new RSAKeyGenParameterSpec(keyLength, exponent);
    }

    /**
     * Inspects the key generation parameters provided and determine if the
     * certificate should be re-generated with new values and if that is the
     * case creates the new certificate.
     * @param alias of the key entry
     * @param authCode of the key entry (only needed for JKS)
     * @param params key generation parameters
     * @param keyStore to query and store the key entry in
     * @param provider of the keystore
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     * @throws OperatorCreationException
     * @throws CertificateException 
     * @throws CryptoTokenOfflineException 
     * @see CryptoTokenHelper#PROPERTY_SELFSIGNED_DN
     * @see CryptoTokenHelper#PROPERTY_SELFSIGNED_SIGNATUREALGORITHM
     * @see CryptoTokenHelper#PROPERTY_SELFSIGNED_VALIDITY
     */
    public static void regenerateCertIfWanted(final String alias, final char[] authCode, final Map<String, Object> params, final KeyStoreDelegator keyStore, final String provider) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, OperatorCreationException, CertificateException, CryptoTokenOfflineException {
        String dn = (String) params.get(PROPERTY_SELFSIGNED_DN);
        Long validity = (Long) params.get(PROPERTY_SELFSIGNED_VALIDITY);
        String signatureAlgorithm = (String) params.get(PROPERTY_SELFSIGNED_SIGNATUREALGORITHM);
        
        // If any of the params are specified, we should re-generate the certificate
        if (dn != null || validity != null || signatureAlgorithm != null) {
            PrivateKey key = null;
            try {
                key = keyStore.aquirePrivateKey(alias, authCode);
                final PublicKey oldPublicKey = keyStore.getPublicKey(alias);
                final X509Certificate newCert = createDummyCertificate(alias, params, new KeyPair(oldPublicKey, key), provider);

                keyStore.setKeyEntry(alias, key, authCode, new Certificate[] { newCert });
            } finally {
                if (key != null) {
                    keyStore.releasePrivateKey(key);
                }
            }
        }
    }
    
    /**
     * Create a dummy certificate with the provided parameters.
     * @param alias to use in the name
     * @param params map of parameters to use
     * @param keyPair where the public key will be in the certificate and the private used to sign it
     * @param provider for the keys
     * @return the new certificate
     * @throws OperatorCreationException
     * @throws CertificateException 
     */
    public static X509Certificate createDummyCertificate(final String alias, final Map<String, Object> params, final KeyPair keyPair, final String provider) throws OperatorCreationException, CertificateException {
        String dn = (String) params.get(PROPERTY_SELFSIGNED_DN);
        Long validity = (Long) params.get(PROPERTY_SELFSIGNED_VALIDITY);
        String signatureAlgorithm = (String) params.get(PROPERTY_SELFSIGNED_SIGNATUREALGORITHM);
        return createDummyCertificate(alias, dn, validity, signatureAlgorithm, keyPair, provider);
    }
    
    private static X509Certificate createDummyCertificate(final String alias, String dn, Long validity, String signatureAlgorithm, final KeyPair keyPair, final String provider) throws OperatorCreationException, CertificateException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Regenerate self signed certificate requested with values: "
                    + "DN: " + dn + ", "
                    + "validity: " + validity + ", "
                    + "signature algorithm: " + signatureAlgorithm);
        }
        // Our default DN
        if (dn == null) {
            dn = getDummyCertificateDN(alias);
        }

        // Our default validity
        if (validity == null) {
            validity = DEFAULT_VALIDITY_S;
        }

        // Our default signature algorithm
        if (signatureAlgorithm == null) {
            signatureAlgorithm = DEFAULT_SIGNATUREALGORITHM;
        }

        return getSelfCertificate(dn, DEFAULT_BACKDATE, validity, signatureAlgorithm, keyPair, provider);
    }
    
    /**
     * Fetches the counter value for number of signing from database for provided public key.
     *
     * @param publicKey public Key associated with signer certificate
     * @param services required for acquiring database service
     * @return long value representing signing counter.
     */
    public static long getNoOfSignings(PublicKey publicKey, final IServices services) {
        long keyUsageCounterValue = 0;
        KeyUsageCounter counter = services.get(IKeyUsageCounterDataService.class).getCounter(KeyUsageCounterHash.create(publicKey));
        if (counter != null) {
            keyUsageCounterValue = counter.getCounter();
        }
        return keyUsageCounterValue;
    }
    
    /**
     * @return True if the JRE has been patched with additional PKCS#11 features
     */
    public static boolean isJREPatched() {
        boolean result = true;
        try {
            Class.forName("sun.security.pkcs11.P11AsymmetricParameterSpec");
            LOG.debug("JRE patched");
        } catch (ClassNotFoundException ex) {
            result = false;
            if (LOG.isDebugEnabled()) {
                LOG.debug("JRE not patched: " + ex.getMessage());
            }
        }
        return result;
    }  
        
    /**
     * Identifies whether KeyPair or Key should be generated for provided keyAlgorithm.
     *
     * @param keyAlgorithm user provided keyAlgorithm
     * @return True if keyAlgorithm identified as Asymmetric
     */
    public static boolean isKeyAlgorithmAsymmetric(String keyAlgorithm) {
        return !isKeyAlgoSymmetric(keyAlgorithm.trim());
    }
    
    private static boolean isKeyAlgoSymmetric(String keyAlgorithm) {
        if (keyAlgorithm.startsWith(SECRET_KEY_PREFIX)) {
            return true;
        } else {
            return Arrays.asList(KNOWNSECRETKEYALGONAMES).contains(keyAlgorithm);
        }
    }
    
    /**
     * Determines Constant value for provided algorithm name with respect to JacKNJI11 Provider.
     * @param algorithm
     * @return
     */
    public static long getProviderAlgoValue(String algorithm) {
        String providerAlgoName = algorithm + CKM_SECRET_KEY_ALGO_SUFFIX;
        Long longValue = MechanismNames.longFromName(providerAlgoName);

        if (longValue == null && algorithm.equals(SECRET_KEY_ALGO_DESede)) {
            longValue = MechanismNames.longFromName(SECRET_KEY_ALGO_Triple_DES + CKM_SECRET_KEY_ALGO_SUFFIX);
        }
        
        if (longValue != null) {
            return longValue;
        } else {
            throw new IllegalArgumentException("Secret key algorithm " + algorithm + " not supported");
        }
    }
    
    /**
     * Determines constant value for provided cipher algorithm name with respect to JacKNJI11 Provider.
     * @param cipherAlgorithm cipher Algorithm name starting with prefix CKM_
     * @return
     */
    public static long getProviderCipherAlgoValue(String cipherAlgorithm) {
        String providerAlgoName = cipherAlgorithm.substring(cipherAlgorithm.indexOf(CKM_PREFIX) + CKM_PREFIX.length());
        Long longValue = MechanismNames.longFromName(providerAlgoName);
        if (longValue != null) {
            return longValue;
        } else {
            throw new IllegalArgumentException("Cipher algorithm " + cipherAlgorithm + " not supported");
        }
    }

    /**
     * Checks that the crypto token is enabled, i.e. that it is not disabled.
     * Otherwise throws an exception.
     *
     * @param config worker configuration
     * @throws CryptoTokenInitializationFailureException in case it is disabled
     * @see SignServerConstants#DISABLED
     */
    public static void checkEnabled(Properties config) throws CryptoTokenInitializationFailureException {
        if (Boolean.parseBoolean(config.getProperty(SignServerConstants.DISABLED))) {
            throw new CryptoTokenInitializationFailureException("Disabled");
        }
    }
    
    /**
     * Utility method to get CKA attribute map from list of provided CKA attribute property.
     *
     * @param attributes list of CKA attribute property
     * @return map of CKA attribute constant as key and its value 
     */
    public static Map<Long, Object> convertCKAAttributeListToMap(List<AttributeProperties.Attribute> attributes) {
        if (attributes == null) {
            return Collections.emptyMap();
        }
        final Map<Long, Object> result = new HashMap<>();
        for (AttributeProperties.Attribute attribute : attributes) {
            result.put(attribute.getId(), attribute.getValue());
        }
        return result;
    }
    
    private static void handleOrdering(List<TokenEntry> filteredEntries, QueryCriteria qc) {
        final List<Elem> elements = qc.getElements();
        final List<Elem> clauses = new ArrayList<>();
        
        // Read requested Ordering from criteria
        CollectionUtils.select(elements, PredicateUtils.instanceofPredicate(Order.class), clauses);
        
        if (!clauses.isEmpty()) {
            if (clauses.size() == 1) {
                Elem elem = clauses.get(0);
                Order order = (Order) elem;
                if (order.getName().equals(TOKEN_ENTRY_FIELDS_KEY_ALIAS)) {
                    Order.Value orderValue = order.getOrder();
                    if (orderValue.equals(Order.Value.ASC)) {
                        TokenEntryKeyAliasOrderByASC ascComparison = new TokenEntryKeyAliasOrderByASC();
                        Collections.sort(filteredEntries, ascComparison);
                    } else { // DESC ordering
                        TokenEntryKeyAliasOrderByDESC descComparison = new TokenEntryKeyAliasOrderByDESC();
                        Collections.sort(filteredEntries, descComparison);
                    }
                } else { // TODO: support for ordering by other column names
                    LOG.warn("Ordering only supported by column name: " + TOKEN_ENTRY_FIELDS_KEY_ALIAS + "/" + TOKEN_ENTRY_FIELDS_ALIAS);
                }
            } else { // TODO: support for ordering by multiple column names as ADMIN WS allows multiple ordering elements
                LOG.warn("Ordering by more than one column name not supported");
            }
        }
    }
    
}
