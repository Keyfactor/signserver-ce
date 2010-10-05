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

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.SignatureException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.Properties;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import org.apache.log4j.Logger;
import org.ejbca.core.model.ca.catoken.PKCS11CAToken;
import org.ejbca.util.keystore.KeyStoreContainer;
import org.ejbca.util.keystore.KeyStoreContainerFactory;
import org.ejbca.util.Base64;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.WorkerConfig;
import org.ejbca.util.CertTools;
import org.signserver.common.KeyTestResult;
import org.signserver.server.KeyUsageCounter;


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
 *
 * @see org.signserver.server.cryptotokens.ICryptoToken
 * @author Tomas Gustavsson, Philip Vendil
 * @version $Id$
 */

public class PKCS11CryptoToken extends CryptoTokenBase implements ICryptoToken,
    IKeyGenerator {

	private static final Logger log = Logger.getLogger(PKCS11CryptoToken.class);

        private Properties properties;

        private char[] authenticationCode;


	public PKCS11CryptoToken() throws InstantiationException{
		catoken = new PKCS11CAToken();
	}

	/**
	 * Method initializing the PKCS11 device
	 *
	 */
	public void init(final int workerId, final Properties props) {
		log.debug(">init");
		String signaturealgoritm = props.getProperty(WorkerConfig.SIGNERPROPERTY_SIGNATUREALGORITHM);
		this.properties = fixUpProperties(props);
		try {
			((PKCS11CAToken)catoken).init(properties, null, signaturealgoritm, workerId);
		} catch(Exception e) {
			log.error("Error initializing PKCS11CryptoToken : " + e.getMessage(),e);
		}
		String authCode = properties.getProperty("pin");
		if (authCode != null) {
			try {
				this.activate(authCode);
			} catch(Exception e) {
				log.error("Error auto activating PKCS11CryptoToken : " + e.getMessage(),e);
			}
		}
		log.debug("<init");
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
        if (log.isDebugEnabled()) {
            log.debug("keyAlgorithm: " + keyAlgorithm + ", keySpec: " + keySpec
                    + ", alias: " + alias);
        }
        try {

            final Provider provider = Security.getProvider(
                getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
            if (log.isDebugEnabled()) {
                log.debug("provider: " + provider);
            }

            // Keyspec for DSA is prefixed with "dsa"
            if (keyAlgorithm != null && keyAlgorithm.equalsIgnoreCase("DSA")
                    && !keySpec.contains("dsa")) {
                keySpec = "dsa" + keySpec;
            }

            KeyStore.ProtectionParameter pp;
            if (authCode == null) {
                log.debug("authCode == null");
                final String pin = properties.getProperty("pin");
                if (pin == null) {
                    log.debug("pin == null");
                    pp = new KeyStore.ProtectionParameter() {};
                } else {
                    log.debug("pin specified");
                    pp = new KeyStore.PasswordProtection(pin.toCharArray());
                }
            } else {
                log.debug("authCode specified");
                pp = new KeyStore.PasswordProtection(authCode);
            }

            final String sharedLibrary
                    = properties.getProperty("sharedLibrary");
            final String slot
                    = properties.getProperty("slot");
            final String attributesFile
                    = properties.getProperty("attributesFile");

            if (log.isDebugEnabled()) {
                log.debug("sharedLibrary: " + sharedLibrary + ", slot: "
                        + slot + ", attributesFile: " + attributesFile);
            }

            final KeyStoreContainer store = KeyStoreContainerFactory
                    .getInstance(KeyStoreContainer.KEYSTORE_TYPE_PKCS11,
                    sharedLibrary, null,
                    slot,
                    attributesFile, pp);
            store.setPassPhraseLoadSave(authCode);
            store.generate(keySpec, alias);
        } catch (Exception ex) {
            log.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        }
    }

    private KeyStore getKeyStore(final char[] authCode)
            throws KeyStoreException {
        KeyStore.ProtectionParameter pp;
        if (authCode == null) {
            log.debug("authCode == null");
            final String pin = properties.getProperty("pin");
            if (pin == null) {
                log.debug("pin == null");
            pp = new KeyStore.ProtectionParameter() {};
        } else {
                log.debug("pin specified");
                pp = new KeyStore.PasswordProtection(pin.toCharArray());
            }
        } else {
            log.debug("authCode specified");
            pp = new KeyStore.PasswordProtection(authCode);
        }

        final Provider provider = Security.getProvider(
                getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
        if (log.isDebugEnabled()) {
            log.debug("provider: " + provider);
        }
        final KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11",
                provider, pp);

        return builder.getKeyStore();
    }

    /**
     * @see ICryptoToken#testKey(java.lang.String, char[])
     */
    public Collection<KeyTestResult> testKey(String alias, char[] authCode)
            throws CryptoTokenOfflineException, KeyStoreException {
        final Collection<KeyTestResult> result
                = new LinkedList<KeyTestResult>();

        final byte signInput[] = "Lillan gick on the roaden ut.".getBytes();

        final KeyStore keyStore = getKeyStore(authCode);

        try {
            final Enumeration<String> e = keyStore.aliases();
            while( e.hasMoreElements() ) {
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
                                publicKeyHash
                                        = createKeyHash(keyPair.getPublic());
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
                            log.error("Error testing key: " + keyAlias, ex);
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

        return result;
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            boolean defaultKey) throws CryptoTokenOfflineException {
        log.debug(">genCertificateRequest PKCS11CryptoToken");
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
            if (log.isDebugEnabled()) {
                log.debug("defaultKey: " + defaultKey);
                log.debug("alias: " + alias);
                log.debug("signatureAlgorithm: "
                        + reqInfo.getSignatureAlgorithm());
                log.debug("subjectDN: " + reqInfo.getSubjectDN());
            }

            try {
                final KeyStore keyStore = getKeyStore(authenticationCode);

                final PrivateKey privateKey = (PrivateKey) keyStore.getKey(
                        alias, authenticationCode);
                final Certificate cert = keyStore.getCertificate(alias);

                if (log.isDebugEnabled()) {
                    log.debug("Public key SHA1: " + CryptoTokenBase.createKeyHash(
                            cert.getPublicKey()));
                    log.debug("Public key SHA256: "
                        + KeyUsageCounter.createKeyHash(cert.getPublicKey()));
                }

                pkcs10 = new PKCS10CertificationRequest(
                        reqInfo.getSignatureAlgorithm(),
                        CertTools.stringToBcX509Name(reqInfo.getSubjectDN()),
                        cert.getPublicKey(), reqInfo.getAttributes(),
                        privateKey,
                        getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
                retval = new Base64SignerCertReqData(Base64.encode(pkcs10.getEncoded()));
            } catch (UnrecoverableKeyException e) {
                log.error("Certificate request error: " + e.getMessage(), e);
            } catch (KeyStoreException e) {
                log.error("Certificate request error: " + e.getMessage(), e);
            } catch (InvalidKeyException e) {
                log.error("Certificate request error: " + e.getMessage(), e);
            } catch (NoSuchAlgorithmException e) {
                log.error("Certificate request error: " + e.getMessage(), e);
            } catch (NoSuchProviderException e) {
                log.error("Certificate request error: " + e.getMessage(), e);
            } catch (SignatureException e) {
                log.error("Certificate request error: " + e.getMessage(), e);
            }

        }
        log.debug("<genCertificateRequest PKCS11CryptoToken");
        return retval;
    }

}
