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
package org.signserver.server;

import java.io.UnsupportedEncodingException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import javax.ejb.EJBException;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.*;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.cryptotokens.IKeyGenerator;

public abstract class BaseProcessable extends BaseWorker implements IProcessable {

    /** Log4j instance for actual implementation class */
    private final transient Logger log = Logger.getLogger(this.getClass());
    
    protected ICryptoToken cryptoToken;
    
    private X509Certificate cert;
    private Collection<Certificate> certChain;

    protected BaseProcessable() {
    }

    public void activateSigner(String authenticationCode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException {
        if (log.isTraceEnabled()) {
            log.trace(">activateSigner");
        }
        
        try {
            ICryptoToken token = getCryptoToken();
        
            if (token == null) {
        	if (log.isDebugEnabled()) {
        		log.debug("Crypto token not found");
        	}
        	return;
            }
            token.activate(authenticationCode);
            
            // Check if certificate matches key
            Certificate certificate = getSigningCertificate();
            if (certificate == null) {
                log.info("Activate: Signer " + workerId + ": No certificate");
            } else {
                if (Arrays.equals(certificate.getPublicKey().getEncoded(),
                    getCryptoToken().getPublicKey(
                    ICryptoToken.PURPOSE_SIGN).getEncoded())) {
                    log.info("Activate: Signer " + workerId
                        + ": Certificate matches key");
                } else {
                    log.info("Activate: Signer " + workerId
                        + ": Certificate does not match key");
                }
            }
            if (log.isTraceEnabled()) {
                log.trace("<activateSigner");
            }
        } catch (SignServerException e) {
            log.error("Failed to get crypto token: " + e.getMessage());
            throw new CryptoTokenOfflineException(e);
        }
    }

    public boolean deactivateSigner() throws CryptoTokenOfflineException {
        if (log.isTraceEnabled()) {
            log.trace(">deactivateSigner");
        }
        
        try {
            ICryptoToken token = getCryptoToken();
            if (token == null) {
        	if (log.isDebugEnabled()) {
        		log.debug("Crypto token not found");
        	}
        	return false;
            }

            boolean ret = getCryptoToken().deactivate();
            if (log.isTraceEnabled()) {
                log.trace("<deactivateSigner");
            }
            return ret;
        } catch (SignServerException e) {
            log.error("Failed to get crypto token: " + e.getMessage());
            throw new CryptoTokenOfflineException(e);
        }
    }

    /**
     * Returns the authentication type configured for this signer.
     * Returns one of the ISigner.AUTHTYPE_ constants or the class path
     * to a custom authenticator. 
     * 
     * default is client certificate authentication.
     */
    public String getAuthenticationType() {
        return config.getProperties().getProperty(WorkerConfig.PROPERTY_AUTHTYPE, IProcessable.AUTHTYPE_CLIENTCERT);
    }

    protected ICryptoToken getCryptoToken() throws SignServerException {
        if (log.isTraceEnabled()) {
            log.trace(">getCryptoToken");
        }
        if (cryptoToken == null) {
            GlobalConfiguration gc = getGlobalConfigurationSession().getGlobalConfiguration();
            try {
                String classpath = gc.getCryptoTokenProperty(workerId, GlobalConfiguration.CRYPTOTOKENPROPERTY_CLASSPATH);
                if (log.isDebugEnabled()) {
                    log.debug("Found cryptotoken classpath: " + classpath);
                }
                if (classpath != null) {
                    Class<?> implClass = Class.forName(classpath);
                    Object obj = implClass.newInstance();
                    cryptoToken = (ICryptoToken) obj;
                    cryptoToken.init(workerId, config.getProperties());
                }
            } catch (CryptoTokenInitializationFailureException e) {
                throw new SignServerException("Failed to initialize crypto token", e);
            } catch (ClassNotFoundException e) {
                throw new SignServerException("Class not found", e);
            } catch (IllegalAccessException iae) {
                throw new SignServerException("Illegal access", iae);
            } catch (InstantiationException ie) {
                throw new SignServerException("Instantiation error", ie);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCryptoToken: " + cryptoToken);
        }

        return cryptoToken;
    }
    
    public int getCryptoTokenStatus() {
        try {
            final int result;
            ICryptoToken token = getCryptoToken();
            
            if (token == null) {
                result = CryptoTokenStatus.STATUS_OFFLINE;
            } else {
                result = token.getCryptoTokenStatus();
            }
            
            return result;
        } catch (SignServerException e) {
            return CryptoTokenStatus.STATUS_OFFLINE;
        }
    }

    /**
     * Method that returns the certificate used when signing
     * @throws CryptoTokenOfflineException 
     */
    public Certificate getSigningCertificate() throws CryptoTokenOfflineException {
        if (cert == null) {
            try {
                if (getCryptoToken() != null) {
                    cert = (X509Certificate) getCryptoToken().getCertificate(ICryptoToken.PURPOSE_SIGN);
                }
            } catch (SignServerException e) {
                log.error("Failed to get crypto token: " + e.getMessage());
                throw new CryptoTokenOfflineException(e);
            }
            if (cert == null) {
                cert = (new ProcessableConfig(config)).getSignerCertificate();
            }
        }
        return cert;
    }

    /**
     * Method that returns the certificate chain used when signing
     * @throws CryptoTokenOfflineException 
     */
    public Collection<Certificate> getSigningCertificateChain() throws CryptoTokenOfflineException {
        if (certChain == null) {
            try {
                ICryptoToken cToken = getCryptoToken();
                if (cToken != null) {
                    certChain = cToken.getCertificateChain(ICryptoToken.PURPOSE_SIGN);
                    if (certChain == null) {
                        log.debug("Signtoken did not contain a certificate chain, looking in config.");
                        certChain = (new ProcessableConfig(config)).getSignerCertificateChain();
                        if (certChain == null) {
                            log.error("Neither Signtoken or ProcessableConfig contains a certificate chain!");
                        }
                    }
                }
            } catch (SignServerException e) {
                log.error("Failed to get crypto token: " + e.getMessage());
                throw new CryptoTokenOfflineException(e);
            }
        }
        return certChain;
    }

    /**
     * Method sending the request info to the signtoken
     * @return the request or null if method isn't supported by signertoken.
     */
    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            final boolean explicitEccParameters, final boolean defaultKey)
            throws CryptoTokenOfflineException {
        if (log.isTraceEnabled()) {
            log.trace(">genCertificateRequest");
        }
        
        try {
            ICryptoToken token = getCryptoToken();
            if (log.isDebugEnabled()) {
                log.debug("Found a crypto token of type: " + token.getClass().getName());
                log.debug("Token status is: " + token.getCryptoTokenStatus());
            }
            ICertReqData data = token.genCertificateRequest(info,
                    explicitEccParameters, defaultKey);
            if (log.isTraceEnabled()) {
                log.trace("<genCertificateRequest");
            }
            
            return data;
        } catch (SignServerException e) {
            log.error("Failed to get crypto token: " + e.getMessage());
            throw new CryptoTokenOfflineException(e);
        }
    }

    /**
     * Method sending the removal request to the signtoken
     */
    public boolean destroyKey(int purpose) {
        try {
            return getCryptoToken().destroyKey(purpose);
        } catch (SignServerException e) {
            log.error("Failed to get crypto token: " + e.getMessage());
            return false;
        }
    }

    /**
     * @see IKeyGenerator#generateKey(java.lang.String, java.lang.String,
     * java.lang.String, char[])
     */
    public void generateKey(final String keyAlgorithm, final String keySpec,
            final String alias, final char[] authCode)
            throws CryptoTokenOfflineException, IllegalArgumentException {
        try {
            ICryptoToken token = getCryptoToken();
            if (token == null) {
                throw new CryptoTokenOfflineException("Crypto token offline");
            } else if (token instanceof IKeyGenerator) {
                ((IKeyGenerator) token).generateKey(keyAlgorithm, keySpec, alias,
                        authCode);
            } else {
                throw new IllegalArgumentException(
                        "Key generation not supported by crypto token");
            }
        } catch (SignServerException e) {
            log.error("Failed to get crypto token: " + e.getMessage());
            throw new CryptoTokenOfflineException(e);
        }
    }

    /**
     * @see IProcessable#testKey(java.lang.String, char[])
     */
    @Override
    public Collection<org.signserver.common.KeyTestResult> testKey(String alias, char[] authCode)
            throws CryptoTokenOfflineException, KeyStoreException {
        try {
            ICryptoToken token = getCryptoToken();
            
            if (token == null) {
                throw new CryptoTokenOfflineException("Crypto token offline");
            }
        
            return token.testKey(alias, authCode);
        } catch (SignServerException e) {
            log.error("Failed to get crypto token: " + e.getMessage());
            throw new CryptoTokenOfflineException(e);
        }
    }
    
    /**
     * Computes an archive id based on the data and the request id.
     * @param data The document to archive
     * @param transactionId The transaction id
     * @return An ArchiveId (hex encoded hash of document+requestid)
     * @throws SignServerException in case of error
     */
    protected String createArchiveId(final byte[] data, final String transactionId) throws SignServerException {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(data);
            return new String(Hex.encode(md.digest(transactionId.getBytes("UTF-8"))), "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            throw new SignServerException("Unable to compute archive id", ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new SignServerException("Unable to compute archive id", ex);
        }
    }
}
