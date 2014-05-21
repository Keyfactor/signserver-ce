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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.ejbca.core.model.util.AlgorithmTools;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.CryptoTokenStatus;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.KeyTestResult;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.SignServerException;
import org.signserver.server.KeyUsageCounterHash;
import static org.signserver.server.cryptotokens.CryptoTokenBase.createKeyHash;
import static org.signserver.server.cryptotokens.CryptoTokenBase.suggestSigAlg;

/**
 * CryptoToken implementation wrapping the new PKCS11CryptoToken from CESeCore.
 * 
 * Note: The mapping between SignServer APIs and CESeCore is not perfect. In 
 * particular the SignServer calls for testing and generating key-pairs takes 
 * an authentication code while the CESeCore ones assumes the token is already 
 * activated. This means that the auth code parameter will be ignored for those
 * methods.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class PKCS11CryptoToken implements ICryptoToken, ICryptoTokenV2 {
    
    private static final Logger LOG = Logger.getLogger(PKCS11CryptoToken.class);

    private static final String PROPERTY_CACHE_PRIVATEKEY = "CACHE_PRIVATEKEY";
    
    
    private final KeyStorePKCS11CryptoToken delegate;

    public PKCS11CryptoToken() throws InstantiationException {
        delegate = new KeyStorePKCS11CryptoToken();
    }
    
    private String keyAlias;
    private String nextKeyAlias;

    private boolean cachePrivateKey;
    private PrivateKey cachedPrivateKey;
    
    @Override
    public void init(int workerId, Properties props) throws CryptoTokenInitializationFailureException {
        try {
            final String attributesValue = props.getProperty(CryptoTokenHelper.PROPERTY_ATTRIBUTES);
            if (attributesValue != null && props.getProperty(CryptoTokenHelper.PROPERTY_ATTRIBUTESFILE) != null) {
                throw new CryptoTokenInitializationFailureException(
                        "Only specify one of " + CryptoTokenHelper.PROPERTY_ATTRIBUTES
                                + " and " + CryptoTokenHelper.PROPERTY_ATTRIBUTESFILE);
            }

            if (attributesValue != null) {
                OutputStream out = null;
                try {
                    File attributesFile = File.createTempFile("attributes-" + workerId + "-", ".tmp");
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Created attributes file: " + attributesFile.getAbsolutePath());
                    }
                    attributesFile.deleteOnExit();
                    out = new FileOutputStream(attributesFile);
                    IOUtils.write(attributesValue, out);
                    props.setProperty(CryptoTokenHelper.PROPERTY_ATTRIBUTESFILE, attributesFile.getAbsolutePath());
                } catch (IOException ex) {
                    throw new CryptoTokenInitializationFailureException("Unable to create attributes file", ex);
                } finally {
                    IOUtils.closeQuietly(out);
                }
            }

            props = CryptoTokenHelper.fixP11Properties(props);

            final String sharedLibraryProperty = props.getProperty("sharedLibrary");
            if (sharedLibraryProperty == null) {
                throw new CryptoTokenInitializationFailureException("Missing SHAREDLIBRARY property");
            }
            final File sharedLibrary = new File(sharedLibraryProperty);
            if (!sharedLibrary.isFile() || !sharedLibrary.canRead()) {
                throw new CryptoTokenInitializationFailureException("The shared library file can't be read: " + sharedLibrary.getAbsolutePath());
            }

            final String slotLabelType = props.getProperty(CryptoTokenHelper.PROPERTY_SLOTLABELTYPE);
            if (slotLabelType == null) {
                throw new CryptoTokenInitializationFailureException("Missing " + CryptoTokenHelper.PROPERTY_SLOTLABELTYPE + " property");
            }
            final String slotLabelValue = props.getProperty(CryptoTokenHelper.PROPERTY_SLOTLABELVALUE);
            if (slotLabelValue == null) {
                throw new CryptoTokenInitializationFailureException("Missing " + CryptoTokenHelper.PROPERTY_SLOTLABELVALUE + " property");
            }

            delegate.init(props, null, workerId);
            
            keyAlias = props.getProperty("defaultKey");
            nextKeyAlias = props.getProperty("nextCertSignKey");
            
            cachePrivateKey = Boolean.parseBoolean(props.getProperty(PROPERTY_CACHE_PRIVATEKEY, Boolean.FALSE.toString()));
            
            if (LOG.isDebugEnabled()) { 
                final StringBuilder sb = new StringBuilder();
                sb.append("keyAlias: ").append(keyAlias).append("\n");
                sb.append("nextKeyAlias: ").append(nextKeyAlias).append("\n");
                sb.append("cachePrivateKey: ").append(cachePrivateKey);
                LOG.debug(sb.toString());
            }
        } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
            LOG.error("Init failed", ex);
            throw new CryptoTokenInitializationFailureException(ex.getMessage());
        } catch (NoSuchSlotException ex) {
            LOG.error("Slot not found", ex);
            throw new CryptoTokenInitializationFailureException(ex.getMessage());
        } catch (NumberFormatException ex) {
            LOG.error("Init failed", ex);
            throw new CryptoTokenInitializationFailureException(ex.getMessage());
        }
    }

    @Override
    public int getCryptoTokenStatus() {
        int result = delegate.getTokenStatus();
        
        if (result == CryptoTokenStatus.STATUS_ACTIVE) {
            result = CryptoTokenStatus.STATUS_OFFLINE;
            try {
                if (LOG.isDebugEnabled()) { 
                    final StringBuilder sb = new StringBuilder();
                    sb.append("keyAlias: ").append(keyAlias).append("\n");
                    sb.append("nextKeyAlias: ").append(nextKeyAlias).append("\n");
                    LOG.debug(sb.toString());
                }
                for (String testKey : new String[]{keyAlias, nextKeyAlias}) {
                    if (testKey != null && !testKey.isEmpty()) {
                        PrivateKey privateKey = delegate.getPrivateKey(testKey);
                        if (privateKey != null) {
                            PublicKey publicKey = delegate.getPublicKey(testKey);
                            testKey(privateKey, publicKey);
                            result = CryptoTokenStatus.STATUS_ACTIVE;
                        }
                    }
                }
            } catch (Throwable th) {
                LOG.error("Error testing activation", th);
            }
        }

        return result;
    }
    
    private void testKey(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        final byte input[] = "Lillan gick pa vagen ut, motte dar en katt...".getBytes();
        final byte signBV[];
        String testSigAlg = (String) AlgorithmTools.getSignatureAlgorithms(publicKey).iterator().next();
        if (testSigAlg == null) {
            testSigAlg = "SHA1WithRSA";
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Testing keys with algorithm: " + publicKey.getAlgorithm());
            LOG.debug("testSigAlg: " + testSigAlg);
            LOG.debug("provider: " + delegate.getSignProviderName());
            LOG.trace("privateKey: " + privateKey);
            LOG.trace("privateKey class: " + privateKey.getClass().getName());
            LOG.trace("publicKey: " + publicKey);
            LOG.trace("publicKey class: " + publicKey.getClass().getName());
        }

        final Signature signSignature = Signature.getInstance(testSigAlg, delegate.getSignProviderName());
        signSignature.initSign(privateKey);
        signSignature.update(input);
        signBV = signSignature.sign();
        if (LOG.isDebugEnabled()) {
            if (signBV != null) {
                LOG.trace("Created signature of size: " + signBV.length);
                LOG.trace("Created signature: " + new String(Hex.encode(signBV)));
            } else {
                LOG.warn("Test signature is null?");
            }
        }

        final Signature verifySignatre = Signature.getInstance(testSigAlg, "BC");
        verifySignatre.initVerify(publicKey);
        verifySignatre.update(input);
        if (!verifySignatre.verify(signBV)) {
            throw new InvalidKeyException("Not possible to sign and then verify with key pair.");
        }
    }

    @Override
    public void activate(String authenticationcode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
        try {
            delegate.activate(authenticationcode.toCharArray());
        } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
            LOG.error("Activate failed", ex);
            throw new CryptoTokenOfflineException(ex);
        } catch (CryptoTokenAuthenticationFailedException ex) {
            LOG.error("Activate failed", ex);
            throw new CryptoTokenAuthenticationFailureException(ex.getMessage());
        }
    }

    @Override
    public boolean deactivate() throws CryptoTokenOfflineException {
        delegate.deactivate();
        return true;
    }

    @Override
    public PrivateKey getPrivateKey(int purpose) throws CryptoTokenOfflineException {
        final PrivateKey result;
        if (purpose == ICryptoToken.PURPOSE_NEXTKEY) {
            result = getPrivateKey(nextKeyAlias);
        } else {
            if (cachePrivateKey && cachedPrivateKey != null) {
                result = cachedPrivateKey;
            } else {
                result = getPrivateKey(keyAlias);
                if (cachePrivateKey) {
                    cachedPrivateKey = result;
                }
            }
        }
        return result;
    }

    @Override
    public PublicKey getPublicKey(int purpose) throws CryptoTokenOfflineException {
        final String alias = purpose == ICryptoToken.PURPOSE_NEXTKEY ? nextKeyAlias : keyAlias;
        return getPublicKey(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) throws CryptoTokenOfflineException {
        try {
            return delegate.getPrivateKey(alias);
        } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
    }

    @Override
    public PublicKey getPublicKey(String alias) throws CryptoTokenOfflineException {
        try {
            return delegate.getPublicKey(alias);
        } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
    }

    @Override
    public String getProvider(int providerUsage) {
        return delegate.getSignProviderName();
    }

    @Override
    public Certificate getCertificate(int purpose) throws CryptoTokenOfflineException {
        return null;
    }

    @Override
    public List<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException {
        return null;
    }

    @Override
    public Certificate getCertificate(String alias) throws CryptoTokenOfflineException {
        return null;
    }

    @Override
    public List<Certificate> getCertificateChain(String alias) throws CryptoTokenOfflineException {
        return null;
    }

    // TODO: The genCertificateRequest method is mostly a duplicate of the one in CryptoTokenBase, PKCS11CryptoTooken, KeyStoreCryptoToken and SoftCryptoToken.
    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            final boolean explicitEccParameters, boolean defaultKey)
            throws CryptoTokenOfflineException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("defaultKey: " + defaultKey);
        }
        final String alias;
        if (defaultKey) {
            alias = keyAlias;
        } else {
            alias = nextKeyAlias;
        }
        return genCertificateRequest(info, explicitEccParameters, alias);
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            final boolean explicitEccParameters, String alias)
            throws CryptoTokenOfflineException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">genCertificateRequest CESeCorePKCS11CryptoToken");
        }
        Base64SignerCertReqData retval = null;
        if (info instanceof PKCS10CertReqInfo) {
            PKCS10CertReqInfo reqInfo = (PKCS10CertReqInfo) info;
            PKCS10CertificationRequest pkcs10;

            if (LOG.isDebugEnabled()) {
                LOG.debug("alias: " + alias);
                LOG.debug("signatureAlgorithm: "
                        + reqInfo.getSignatureAlgorithm());
                LOG.debug("subjectDN: " + reqInfo.getSubjectDN());
                LOG.debug("explicitEccParameters: " + explicitEccParameters);
            }

            try {
                final PrivateKey privateKey = delegate.getPrivateKey(alias);
                PublicKey publicKey = delegate.getPublicKey(alias);

                // Handle ECDSA key with explicit parameters
                if (explicitEccParameters
                        && publicKey.getAlgorithm().contains("EC")) {
                    publicKey = ECKeyUtil.publicToExplicitParameters(publicKey,
                            "BC");
                }

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Public key SHA1: " + CryptoTokenBase.createKeyHash(
                            publicKey));
                    LOG.debug("Public key SHA256: "
                            + KeyUsageCounterHash.create(publicKey));
                }

                // Generate request
                final JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(CertTools.stringToBCDNString(reqInfo.getSubjectDN())), publicKey);
                final ContentSigner contentSigner = new JcaContentSignerBuilder(reqInfo.getSignatureAlgorithm()).setProvider(getProvider(ICryptoToken.PROVIDERUSAGE_SIGN)).build(privateKey);
                pkcs10 = builder.build(contentSigner);
                retval = new Base64SignerCertReqData(Base64.encode(pkcs10.getEncoded()));
            } catch (IOException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            } catch (OperatorCreationException e) {
                LOG.error("Certificate request error: signer could not be initialized", e);
            } catch (NoSuchAlgorithmException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            } catch (NoSuchProviderException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            } catch (org.cesecore.keys.token.CryptoTokenOfflineException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
                throw new CryptoTokenOfflineException(e);
            }

        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("<genCertificateRequest CESeCorePKCS11CryptoToken");
        }
        return retval;
    }

    /**
     * Method not supported.
     */
    @Override
    public boolean destroyKey(int purpose) {
        return false;
    }
    
    @Override
    public boolean removeKey(String alias) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
        return CryptoTokenHelper.removeKey(getKeyStore(), alias);
    }

    @Override
    public Collection<KeyTestResult> testKey(String alias, char[] authCode) throws CryptoTokenOfflineException, KeyStoreException {
        final KeyStore keyStore = delegate.getActivatedKeyStore();
        return CryptoTokenHelper.testKey(keyStore, alias, authCode, keyStore.getProvider().getName());
    }

    @Override
    public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
        return delegate.getActivatedKeyStore();
    }

    @Override
    public void generateKey(String keyAlgorithm, String keySpec, String alias, char[] authCode) throws CryptoTokenOfflineException, IllegalArgumentException {
        if (keySpec == null) {
            throw new IllegalArgumentException("Missing keyspec parameter");
        }
        if (alias == null) {
            throw new IllegalArgumentException("Missing alias parameter");
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("keyAlgorithm: " + keyAlgorithm + ", keySpec: " + keySpec
                    + ", alias: " + alias);
        }
        // Keyspec for DSA is prefixed with "dsa"
        if (keyAlgorithm != null && keyAlgorithm.equalsIgnoreCase("DSA")
                && !keySpec.contains("dsa")) {
            keySpec = "dsa" + keySpec;
        }
        try {
            delegate.generateKeyPair(keySpec, alias);
        } catch (Exception ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        }
    }

    private static class KeyStorePKCS11CryptoToken extends org.cesecore.keys.token.PKCS11CryptoToken {

        public KeyStorePKCS11CryptoToken() throws InstantiationException {
            super();
        }
        
        public KeyStore getActivatedKeyStore() throws CryptoTokenOfflineException {
            try {
                return getKeyStore();
            } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
                throw new CryptoTokenOfflineException(ex);
            }
        }
    }
    
}
