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
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.PredicateUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.util.CertTools;
import org.cesecore.util.QueryParameterException;
import org.cesecore.util.query.Elem;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.clauses.Order;
import org.cesecore.util.query.elems.LogicOperator;
import org.cesecore.util.query.elems.Operation;
import org.cesecore.util.query.elems.Term;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.KeyTestResult;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.QueryException;
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
    
    private static final long DEFAULT_BACKDATE = (long) 10 * 60; // 10 minutes in seconds
    private static final long DEFAULT_VALIDITY_S = (long) 30 * 24 * 60 * 60 * 365; // 30 year in seconds
    private static final String DEFAULT_SIGNATUREALGORITHM = "SHA1withRSA"; // Legacy default

    public enum TokenEntryFields {
        /** Key alias of entry. */
        alias,
        
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

        final Collection<KeyTestResult> result = new LinkedList<>();

        try {
            final Enumeration<String> e = keyStore.aliases();
            while (e.hasMoreElements()) {
                final String keyAlias = e.nextElement();
                if (alias.equalsIgnoreCase(ICryptoTokenV4.ALL_KEYS)
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
                        } catch (InvalidKeyException | KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | UnrecoverableKeyException ex) {
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
        final Base64SignerCertReqData retval;
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
                final JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(CertTools.stringToBCDNString(reqInfo.getSubjectDN())), publicKey);
                final ContentSigner contentSigner = new JcaContentSignerBuilder(reqInfo.getSignatureAlgorithm()).setProvider(signatureProvider).build(privateKey);
                pkcs10 = builder.build(contentSigner);
                retval = new Base64SignerCertReqData(Base64.encode(pkcs10.getEncoded()));
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
        final String alg;
        if (key instanceof ECKey) {
            alg = "SHA256withECDSA";
        } else if (key instanceof RSAKey) {
            alg = "SHA256withRSA";
        } else if (key instanceof DSAKey) {
            alg = "SHA256withDSA";
        } else {
            alg = null;
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
        return dn.contains(CryptoTokenHelper.SUBJECT_DUMMY)
                    || (dn.contains(CESECORE_SUBJECT_DN_6_8))
                    || (dn.contains(CESECORE_SUBJECT_DUMMY_CN) && dn.contains(CESECORE_SUBJECT_DUMMY_L) && dn.contains(CESECORE_SUBJECT_DUMMY_C));
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
        return "CN=" + commonName + ", " + CryptoTokenHelper.SUBJECT_DUMMY + ", C=SE";
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

        return new JcaX509CertificateConverter().getCertificate(cg.build(contentSigner));
    }

    public static TokenSearchResults searchTokenEntries(final KeyStore keyStore, final int startIndex, final int max, final QueryCriteria qc, final boolean includeData) throws CryptoTokenOfflineException, QueryException {
        final TokenSearchResults result;
        try {
            final ArrayList<TokenEntry> tokenEntries = new ArrayList<>();
            final Enumeration<String> e = keyStore.aliases(); // We assume the order is the same for every call unless entries has been added or removed
            
            final long maxIndex = (long) startIndex + max;
            for (int i = 0; i < maxIndex && e.hasMoreElements();) {
                final String keyAlias = e.nextElement();
                
                final String type;
                if (keyStore.entryInstanceOf(keyAlias, KeyStore.PrivateKeyEntry.class)) {
                    type = TokenEntry.TYPE_PRIVATEKEY_ENTRY;
                } else if (keyStore.entryInstanceOf(keyAlias, KeyStore.SecretKeyEntry.class)) {
                    type = TokenEntry.TYPE_SECRETKEY_ENTRY;
                } else if (keyStore.entryInstanceOf(keyAlias, KeyStore.TrustedCertificateEntry.class)) {
                    type = TokenEntry.TYPE_TRUSTED_ENTRY;
                }  else {
                    type = null;
                }
                
                TokenEntry entry = new TokenEntry(keyAlias, type);
                
                if (shouldBeIncluded(entry, qc)) {
                    if (i < startIndex) {
                        i++;
                        continue;
                    }

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("checking keyAlias: " + keyAlias);
                    }

                    // Add additional data
                    if (includeData) {
                        Map<String, String> info = new HashMap<>();
                        try {
                            Date creationDate = keyStore.getCreationDate(keyAlias);
                            entry.setCreationDate(creationDate);
                        } catch (ProviderException ex) {} // NOPMD: We ignore if it is not supported

                        if (TokenEntry.TYPE_PRIVATEKEY_ENTRY.equals(type)) {
                            final Certificate[] chain = keyStore.getCertificateChain(keyAlias);
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
                            }
                            try {
                                entry.setParsedChain(chain);
                            } catch (CertificateEncodingException ex) {
                                info.put("Error", ex.getMessage());
                                LOG.error("Certificate could not be encoded for alias: " + keyAlias, ex);
                            }
                        } else if (TokenEntry.TYPE_TRUSTED_ENTRY.equals(type)) {
                            Certificate certificate = keyStore.getCertificate(keyAlias);
                            try {
                                entry.setParsedTrustedCertificate(certificate);
                            } catch (CertificateEncodingException ex) {
                                info.put("Error", ex.getMessage());
                                LOG.error("Certificate could not be encoded for alias: " + keyAlias, ex);
                            }
                        } else if (TokenEntry.TYPE_SECRETKEY_ENTRY.equals(type)) {
                            try {
                                KeyStore.Entry entry1 = keyStore.getEntry(keyAlias, null);
                                SecretKey secretKey = ((KeyStore.SecretKeyEntry) entry1).getSecretKey();

                                info.put(INFO_KEY_ALGORITHM, secretKey.getAlgorithm());
                                //info.put(INFO_KEY_SPECIFICATION, AlgorithmTools.getKeySpecification(chain[0].getPublicKey())); // TODO: Key specification support for secret keys
                            } catch (NoSuchAlgorithmException | UnrecoverableEntryException ex) {
                                info.put("Error", ex.getMessage());
                                LOG.error("Unable to get secret key for alias: " + keyAlias, ex);
                            }
                        }
                        entry.setInfo(info);
                    }
                    tokenEntries.add(entry);

                    // Increase index
                    i++;
                }
            }
            result = new TokenSearchResults(tokenEntries, e.hasMoreElements());
        } catch (KeyStoreException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
        return result;
    }
    public static final String INFO_KEY_SPECIFICATION = "Key specification";
    public static final String INFO_KEY_ALGORITHM = "Key algorithm";
    public static final String INFO_KEY_PUBLIC_EXPONENT = "Public exponent";
    
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
            case alias: {
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
    public static void ensureNewPublicKeyMatchesOld(KeyStore keyStore, String alias, Certificate newCertificate) throws KeyStoreException, CryptoTokenOfflineException {
        Certificate oldCert = keyStore.getCertificate(alias);
        if (!oldCert.getPublicKey().equals(newCertificate.getPublicKey())) {
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
    public static AlgorithmParameterSpec getPublicExponentParamSpecForRSA(final String keySpec)
        throws InvalidAlgorithmParameterException {
        final String[] parts = keySpec.split("exp");

        if (parts.length != 2) {
            throw new InvalidAlgorithmParameterException("Invalid specification of public exponent");
        }

        final int keyLength = Integer.parseInt(parts[0].trim());
        final String exponentString = parts[1].trim();
        final BigInteger exponent;

        if (exponentString.startsWith("0x")) {
            exponent =
                    new BigInteger(exponentString.substring(2), 16);
        } else {
            exponent = new BigInteger(exponentString);
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
     * @see CryptoTokenHelper#PROPERTY_SELFSIGNED_DN
     * @see CryptoTokenHelper#PROPERTY_SELFSIGNED_SIGNATUREALGORITHM
     * @see CryptoTokenHelper#PROPERTY_SELFSIGNED_VALIDITY
     */
    public static void regenerateCertIfWanted(final String alias, final char[] authCode, final Map<String, Object> params, final KeyStore keyStore, final String provider) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, OperatorCreationException, CertificateException {
        String dn = (String) params.get(PROPERTY_SELFSIGNED_DN);
        Long validity = (Long) params.get(PROPERTY_SELFSIGNED_VALIDITY);
        String signatureAlgorithm = (String) params.get(PROPERTY_SELFSIGNED_SIGNATUREALGORITHM);

        // If any of the params are specified, we should re-generate the certificate
        if (dn != null || validity != null || signatureAlgorithm != null) {
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
            
            final PrivateKey key = (PrivateKey) keyStore.getKey(alias, authCode);
            final X509Certificate oldCert = (X509Certificate) keyStore.getCertificate(alias);
            final X509Certificate newCert = getSelfCertificate(dn, DEFAULT_BACKDATE, validity, signatureAlgorithm, new KeyPair(oldCert.getPublicKey(), key), provider);

            keyStore.setKeyEntry(alias, key, authCode, new Certificate[] { newCert });
        }
    }
}
