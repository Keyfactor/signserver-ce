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
import java.security.*;
import java.security.cert.Certificate;
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
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.ejbca.core.model.ca.catoken.PKCS11CAToken;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyStoreContainer;
import org.ejbca.util.keystore.KeyStoreContainerFactory;
import org.signserver.common.*;
import org.signserver.server.KeyUsageCounterHash;

/**
 * Class used to connect to a PKCS11 HSM.
 *
 * Properties:
 *   sharedLibrary
 *   slot
 *   defaultKey
 *   pin
 *   attributesFile
 *
 * @see org.signserver.server.cryptotokens.ICryptoToken
 * @author Tomas Gustavsson, Philip Vendil
 * @version $Id$
 */
public class PKCS11CryptoToken extends CryptoTokenBase implements ICryptoToken,
        IKeyGenerator {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(PKCS11CryptoToken.class);
    
    private Properties properties;

    private char[] authenticationCode;

    public PKCS11CryptoToken() throws InstantiationException {
        catoken = new PKCS11CAToken();
    }

    /**
     * Method initializing the PKCS11 device
     *
     */
    public void init(final int workerId, final Properties props) {
        LOG.debug(">init");
        String signaturealgoritm = props.getProperty(WorkerConfig.SIGNERPROPERTY_SIGNATUREALGORITHM);
        this.properties = fixUpProperties(props);
        try {
            ((PKCS11CAToken) catoken).init(properties, null, signaturealgoritm, workerId);
        } catch (Exception e) {
            LOG.error("Error initializing PKCS11CryptoToken : " + e.getMessage(), e);
        }
        String authCode = properties.getProperty("pin");
        if (authCode != null) {
            try {
                this.activate(authCode);
            } catch (Exception e) {
                LOG.error("Error auto activating PKCS11CryptoToken : " + e.getMessage(), e);
            }
        }
        LOG.debug("<init");
    }

    @Override
    public void activate(String authenticationcode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException {
        this.authenticationCode = authenticationcode == null ? null
                : authenticationcode.toCharArray();
        super.activate(authenticationcode);
    }

    /**
     * @see IKeyGenerator#generateKey(java.lang.String, java.lang.String, java.lang.String, char[])
     */
    public void generateKey(final String keyAlgorithm, String keySpec,
            String alias, char[] authCode) throws CryptoTokenOfflineException,
            IllegalArgumentException {

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
        try {

            final Provider provider = Security.getProvider(
                    getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
            if (LOG.isDebugEnabled()) {
                LOG.debug("provider: " + provider);
            }

            // Keyspec for DSA is prefixed with "dsa"
            if (keyAlgorithm != null && keyAlgorithm.equalsIgnoreCase("DSA")
                    && !keySpec.contains("dsa")) {
                keySpec = "dsa" + keySpec;
            }

            KeyStore.ProtectionParameter pp;
            if (authCode == null) {
                LOG.debug("authCode == null");
                final String pin = properties.getProperty("pin");
                if (pin != null) {
                    LOG.debug("pin specified");
                    pp = new KeyStore.PasswordProtection(pin.toCharArray());
                } else if (authenticationCode != null) {
                    LOG.debug("Using autentication code");
                    pp = new KeyStore.PasswordProtection(authenticationCode);
                } else {
                    LOG.debug("pin == null");
                    pp = new KeyStore.ProtectionParameter() {
                    };
                }
            } else {
                LOG.debug("authCode specified");
                pp = new KeyStore.PasswordProtection(authCode);
            }

            final String sharedLibrary = properties.getProperty("sharedLibrary");
            final String slot = properties.getProperty("slot");
            final String attributesFile = properties.getProperty("attributesFile");

            if (LOG.isDebugEnabled()) {
                LOG.debug("sharedLibrary: " + sharedLibrary + ", slot: "
                        + slot + ", attributesFile: " + attributesFile);
            }

            final KeyStoreContainer store = KeyStoreContainerFactory.getInstance(KeyStoreContainer.KEYSTORE_TYPE_PKCS11,
                    sharedLibrary, null,
                    slot,
                    attributesFile, pp);
            store.setPassPhraseLoadSave(authCode);
            store.generate(keySpec, alias);
        } catch (Exception ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        }
    }

    private KeyStore getKeyStore(final char[] authCode)
            throws KeyStoreException {
        KeyStore.ProtectionParameter pp;
        if (authCode == null) {
            LOG.debug("authCode == null");
            final String pin = properties.getProperty("pin");
            if (pin == null) {
                LOG.debug("pin == null");
                pp = new KeyStore.ProtectionParameter() {};
            } else {
                LOG.debug("pin specified");
                pp = new KeyStore.PasswordProtection(pin.toCharArray());
            }
        } else {
            LOG.debug("authCode specified");
            pp = new KeyStore.PasswordProtection(authCode);
        }

        final Provider provider = Security.getProvider(
                getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
        if (LOG.isDebugEnabled()) {
            LOG.debug("provider: " + provider);
        }
        final KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11",
                provider, pp);

        return builder.getKeyStore();
    }

    /**
     * @see ICryptoToken#testKey(java.lang.String, char[])
     */
    @Override
    public Collection<KeyTestResult> testKey(String alias, char[] authCode)
            throws CryptoTokenOfflineException, KeyStoreException {
        LOG.debug(">testKey");
        final Collection<KeyTestResult> result = new LinkedList<KeyTestResult>();

        final byte signInput[] = "Lillan gick on the roaden ut.".getBytes();

        final KeyStore keyStore = getKeyStore(authCode);

        try {
            final Enumeration<String> e = keyStore.aliases();
            while (e.hasMoreElements()) {
                final String keyAlias = e.nextElement();
                if (alias.equalsIgnoreCase(ICryptoToken.ALL_KEYS)
                        || alias.equals(keyAlias)) {
                    if (keyStore.isKeyEntry(keyAlias)) {
                        String status;
                        String publicKeyHash = null;
                        boolean success = false;
                        try {
                            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, authCode);
                            final Certificate cert = keyStore.getCertificate(keyAlias);
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
                                        + keyAlias + ". No certificate exists.";
                            }
                        } catch (ClassCastException ce) {
                            status = "Not testing keys with alias "
                                    + keyAlias + ". Not a private key.";
                        } catch (Exception ex) {
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

        LOG.debug("<testKey");
        return result;
    }

    // TODO: The genCertificateRequest method is mostly a duplicate of the one in CryptoTokenBase, PKCS11CryptoTooken, KeyStoreCryptoToken and SoftCryptoToken.
    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            final boolean explicitEccParameters, boolean defaultKey)
            throws CryptoTokenOfflineException {
        LOG.debug(">genCertificateRequest PKCS11CryptoToken");
        Base64SignerCertReqData retval = null;
        if (info instanceof PKCS10CertReqInfo) {
            PKCS10CertReqInfo reqInfo = (PKCS10CertReqInfo) info;
            PKCS10CertificationRequest pkcs10;

            final String alias;
            if (defaultKey) {
                alias = properties.getProperty("defaultKey");
            } else {
                alias = properties.getProperty("nextCertSignKey");
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
                final KeyStore keyStore = getKeyStore(authenticationCode);

                final PrivateKey privateKey = (PrivateKey) keyStore.getKey(
                        alias, authenticationCode);
                final Certificate cert = keyStore.getCertificate(alias);
                if (cert == null) {
                    throw new CryptoTokenOfflineException("Certificate request error: No key with the configured alias");
                }

                PublicKey publicKey = cert.getPublicKey();

                // Handle ECDSA key with explicit parameters
                if (explicitEccParameters
                        && publicKey.getAlgorithm().contains("EC")) {
                    publicKey = ECKeyUtil.publicToExplicitParameters(publicKey,
                            "BC");
                }

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Public key SHA1: " + CryptoTokenBase.createKeyHash(
                            cert.getPublicKey()));
                    LOG.debug("Public key SHA256: "
                            + KeyUsageCounterHash.create(cert.getPublicKey()));
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
            } catch (UnrecoverableKeyException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            } catch (KeyStoreException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            } catch (NoSuchAlgorithmException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            } catch (NoSuchProviderException e) {
                LOG.error("Certificate request error: " + e.getMessage(), e);
            }

        }
        LOG.debug("<genCertificateRequest PKCS11CryptoToken");
        return retval;
    }

    public KeyStore getKeyStore() throws UnsupportedOperationException,
            CryptoTokenOfflineException, KeyStoreException {
        return getKeyStore(authenticationCode); // TODO: check loaded etc
    }
}
