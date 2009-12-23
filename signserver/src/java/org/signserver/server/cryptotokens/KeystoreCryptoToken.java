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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.SignerStatus;

/**
 * Class that uses a PKCS12 or JKS file on the file system for signing. Only one
 * key and purpose is supported the same key for all purposes will be returned.
 *
 * loads on activation and releases the keys from memory when deactivating
 *
 * Available properties are:
 * KEYSTOREPATH : The full path to the key store to load. (required)
 * KEYSTOREPASSWORD : The password that locks the key store.
 * STORETYPE : PKCS12 or JKS. (required)
 *
 * @author Philip Vendil
 * $Id$
 */
public class KeystoreCryptoToken implements ICryptoToken {

    private static final Logger LOG = Logger.getLogger(KeystoreCryptoToken.class);

    public static final String KEYSTOREPATH = "KEYSTOREPATH";
    public static final String KEYSTOREPASSWORD = "KEYSTOREPASSWORD";
    public static final String KEYSTORETYPE = "KEYSTORETYPE";

    public static final String TYPE_PKCS12 = "PKCS12";
    public static final String TYPE_JKS = "JKS";

    private String keystorepath = null;
    private String keystorepassword = null;

    private PrivateKey privKey = null;
    private X509Certificate cert = null;
    private Collection<Certificate> certChain = null;
    private String provider;
    private String keystoretype;

    /**
     * @see org.signserver.server.cryptotokens.ICryptoToken#init(java.util.Properties)
     */
    public void init(int workerId, Properties props) {
        keystorepath = props.getProperty(KEYSTOREPATH);
        keystorepassword = props.getProperty(KEYSTOREPASSWORD);
        keystoretype = props.getProperty(KEYSTORETYPE);
    }

    /**
     * Returns true if the key store was properly loaded.
     *
     * @see org.signserver.server.cryptotokens.ICryptoToken#getCryptoTokenStatus()
     *
     */
    public int getCryptoTokenStatus() {
        if (privKey != null && cert != null) {
            return SignerStatus.STATUS_ACTIVE;
        }

        return SignerStatus.STATUS_OFFLINE;
    }

    /**
     * Loads the key store into memory
     *
     * @see org.signserver.server.cryptotokens.ICryptoToken#activate(java.lang.String)
     */
    public void activate(String authenticationcode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Keystore type is " + keystoretype +
                    " and path is " + keystorepath);
        }

        try {
            KeyStore ks;
            if (TYPE_PKCS12.equalsIgnoreCase(keystoretype)) {
                ks = KeyStore.getInstance("PKCS12", "BC");
            } else {
                ks = KeyStore.getInstance("JKS");
            }
            this.provider = ks.getProvider().getName();

            if (keystorepath == null) {
                throw new FileNotFoundException("Missing property "
                        + KeystoreCryptoToken.KEYSTOREPATH + ".");
            }
            InputStream in = new FileInputStream(keystorepath);
            ks.load(in, authenticationcode.toCharArray());
            in.close();

            // Find the key private key entry in the keystore
            Enumeration<String> e = ks.aliases();
            Object o = null;
            PrivateKey keystorePrivKey = null;

            while (e.hasMoreElements()) {
                o = e.nextElement();

                if (o instanceof String) {
                    if ((ks.isKeyEntry((String) o)) &&
                            ((keystorePrivKey = (PrivateKey) ks.getKey((String) o, authenticationcode.toCharArray())) != null)) {
                        LOG.debug("Aliases " + o + " is KeyEntry.");

                        break;
                    }
                }
            }
            privKey = keystorePrivKey;

            //Certificate chain[] = ks.getCertificateChain((String) o);
            Certificate[] chain = KeyTools.getCertChain(ks, (String) o);
            certChain = new ArrayList<Certificate>();
            for (int i = 0; i < chain.length; i++) {
                certChain.add(chain[i]);
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Loaded certificate chain with length " + chain.length + " from keystore.");
            }

            cert = (X509Certificate) chain[0];
        } catch (KeyStoreException e1) {
            LOG.error("Error :", e1);
            throw new CryptoTokenAuthenticationFailureException("KeyStoreException " + e1.getMessage());
        } catch (FileNotFoundException e) {
            LOG.error("Error :", e);
            throw new CryptoTokenAuthenticationFailureException("Keystore file not found : " + e.getMessage());
        } catch (NoSuchProviderException e1) {
            LOG.error("Error :", e1);
            throw new CryptoTokenAuthenticationFailureException("NoSuchProviderException " + e1.getMessage());
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Error :", e);
            throw new CryptoTokenAuthenticationFailureException("NoSuchAlgorithmException " + e.getMessage());
        } catch (CertificateException e) {
            LOG.error("Error :", e);
            throw new CryptoTokenAuthenticationFailureException("CertificateException " + e.getMessage());
        } catch (IOException e) {
            LOG.error("Error :", e);
            throw new CryptoTokenAuthenticationFailureException("IOException " + e.getMessage());
        } catch (UnrecoverableKeyException e) {
            LOG.error("Error :", e);
            throw new CryptoTokenAuthenticationFailureException("UnrecoverableKeyException " + e.getMessage());
        }
    }

    /**
     * Method that clear the key data from memory.
     *
     * @see org.signserver.server.cryptotokens.ICryptoToken#deactivate()
     */
    public boolean deactivate() {
        privKey = null;
        cert = null;
        return true;
    }

    /**
     * Returns the same private key for all purposes.
     * @see org.signserver.server.cryptotokens.ICryptoToken#getPrivateKey(int)
     */
    public PrivateKey getPrivateKey(int purpose)
            throws CryptoTokenOfflineException {

        if (privKey == null) {
            if (keystorepassword != null) {
                try {
                    activate(keystorepassword);
                } catch (CryptoTokenAuthenticationFailureException e) {
                    throw new CryptoTokenOfflineException("Error trying to autoactivating the keystore, wrong password set? " + e.getMessage());
                }
            } else {
                throw new CryptoTokenOfflineException("Signtoken isn't active.");
            }
        }

        return privKey;
    }

    /**
     * Returns the same public key for all purposes.
     * @see org.signserver.server.cryptotokens.ICryptoToken#getPublicKey(int)
     */
    public PublicKey getPublicKey(int purpose) throws CryptoTokenOfflineException {

        if (cert == null) {
            if (keystorepassword != null) {
                try {
                    activate(keystorepassword);
                } catch (CryptoTokenAuthenticationFailureException e) {
                    throw new CryptoTokenOfflineException("Error trying to autoactivating the keystore, wrong password set? " + e.getMessage());
                }
            } else {
                throw new CryptoTokenOfflineException("Signtoken isn't active.");
            }
        }


        return cert.getPublicKey();
    }

    /**
     * Always returns BC
     * @see org.signserver.server.cryptotokens.ICryptoToken#getProvider()
     */
    public String getProvider(int providerUsage) {
        return provider;
    }

    public Certificate getCertificate(int purpose) throws CryptoTokenOfflineException {
        if (cert == null) {
            if (keystorepassword != null) {
                try {
                    activate(keystorepassword);
                } catch (CryptoTokenAuthenticationFailureException e) {
                    throw new CryptoTokenOfflineException("Error trying to autoactivating the keystore, wrong password set? " + e.getMessage());
                }
            } else {
                throw new CryptoTokenOfflineException("Signtoken isn't active.");
            }
        }


        return cert;
    }

    public Collection<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException {
        if (certChain == null) {
            if (keystorepassword != null) {
                try {
                    activate(keystorepassword);
                } catch (CryptoTokenAuthenticationFailureException e) {
                    throw new CryptoTokenOfflineException("Error trying to autoactivating the keystore, wrong password set? " + e.getMessage());
                }
            } else {
                throw new CryptoTokenOfflineException("Signtoken isn't active.");
            }
        }


        return certChain;
    }

    /**
     * Method not supported
     */
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info) throws CryptoTokenOfflineException {
        LOG.error("genCertificateRequest was called, but is not supported for this sign token.");
        return null;
    }

    /**
     * Method not supported
     */
    public boolean destroyKey(int purpose) {
        return false;
    }
}
