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
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.KeyTestResult;
import org.signserver.common.PKCS10CertReqInfo;
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
public class PKCS11CryptoToken implements ICryptoToken, IKeyGenerator {
    
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
            props = CryptoTokenHelper.fixP11Properties(props);
            
            if (props.getProperty("sharedLibrary") == null) {
                throw new CryptoTokenInitializationFailureException("Missing SHAREDLIBRARY property");
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
        }
    }

    @Override
    public int getCryptoTokenStatus() {
        return delegate.getTokenStatus();
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
        try {
            final PrivateKey result;
            if (purpose == ICryptoToken.PURPOSE_NEXTKEY) {
                result = delegate.getPrivateKey(nextKeyAlias);
            } else {
                if (cachePrivateKey && cachedPrivateKey != null) {
                    result = cachedPrivateKey;
                } else {
                    result = delegate.getPrivateKey(keyAlias);
                    if (cachePrivateKey) {
                        cachedPrivateKey = result;
                    }
                }
            }
            return result;
        } catch (org.cesecore.keys.token.CryptoTokenOfflineException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
    }

    @Override
    public PublicKey getPublicKey(int purpose) throws CryptoTokenOfflineException {
        final String alias = purpose == ICryptoToken.PURPOSE_NEXTKEY ? nextKeyAlias : keyAlias;
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

    // TODO: The genCertificateRequest method is mostly a duplicate of the one in CryptoTokenBase, PKCS11CryptoTooken, KeyStoreCryptoToken and SoftCryptoToken.
    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            final boolean explicitEccParameters, boolean defaultKey)
            throws CryptoTokenOfflineException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">genCertificateRequest CESeCorePKCS11CryptoToken");
        }
        Base64SignerCertReqData retval = null;
        if (info instanceof PKCS10CertReqInfo) {
            PKCS10CertReqInfo reqInfo = (PKCS10CertReqInfo) info;
            PKCS10CertificationRequest pkcs10;

            final String alias;
            if (defaultKey) {
                alias = keyAlias;
            } else {
                alias = nextKeyAlias;
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("defaultKey: " + defaultKey);
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
    public Collection<KeyTestResult> testKey(String alias, char[] authCode) throws CryptoTokenOfflineException, KeyStoreException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">testKey");
        }
        final Collection<KeyTestResult> result = new LinkedList<KeyTestResult>();

        final byte signInput[] = "Lillan gick on the roaden ut.".getBytes();

        //final KeyStore keyStore = getKeyStore(authCode);
        final KeyStore keyStore = delegate.getActivatedKeyStore();

        try {
            final Enumeration<String> e = keyStore.aliases();
            while (e.hasMoreElements()) {
                final String a = e.nextElement();
                if (alias.equalsIgnoreCase(ICryptoToken.ALL_KEYS)
                        || alias.equals(a)) {
                    if (keyStore.isKeyEntry(a)) {
                        String status;
                        String publicKeyHash = null;
                        boolean success = false;
                        try {
                            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(a, authCode);
                            final Certificate cert = keyStore.getCertificate(a);
                            if (cert != null) {
                                final KeyPair keyPair = new KeyPair(cert.getPublicKey(), privateKey);
                                publicKeyHash = createKeyHash(keyPair.getPublic());
                                final String sigAlg = suggestSigAlg(keyPair.getPublic());
                                if (sigAlg == null) {
                                    status = "Unknown key algorithm: "
                                            + keyPair.getPublic().getAlgorithm();
                                } else {
                                    Signature signature = Signature.getInstance(sigAlg, keyStore.getProvider());
                                    signature.initSign(keyPair.getPrivate());
                                    signature.update(signInput);
                                    byte[] signBA = signature.sign();

                                    Signature verifySignature = Signature.getInstance(sigAlg);
                                    verifySignature.initVerify(keyPair.getPublic());
                                    verifySignature.update(signInput);
                                    success = verifySignature.verify(signBA);
                                    status = success ? "" : "Test signature inconsistent";
                                }
                            } else {
                                status = "Not testing keys with alias "
                                        + a + ". No certificate exists.";
                            }
                        } catch (ClassCastException ce) {
                            status = "Not testing keys with alias "
                                    + a + ". Not a private key.";
                        } catch (Exception ex) {
                            LOG.error("Error testing key: " + a, ex);
                            status = ex.getMessage();
                        }
                        result.add(new KeyTestResult(a, success, status,
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
