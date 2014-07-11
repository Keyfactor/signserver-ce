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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.*;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.cryptotokens.IKeyGenerator;
import org.signserver.server.cryptotokens.IKeyRemover;
import org.signserver.server.cryptotokens.ICryptoTokenV2;

public abstract class BaseProcessable extends BaseWorker implements IProcessable, IKeyRemover {

    /** Log4j instance for actual implementation class */
    private final transient Logger log = Logger.getLogger(this.getClass());

    private static final String FAILED_TO_GET_CRYPTO_TOKEN_ = "Failed to get crypto token: ";
    private static final String DEFAULT_ = "DEFAULT.";

    protected ICryptoToken cryptoToken;
    
    private X509Certificate cert;
    private List<Certificate> certChain;

    /**
     * Holds fatal errors gathered when initing the crypto token.
     */
    private List<String> cryptoTokenFatalErrors;
    
    protected BaseProcessable() {
    }

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        cryptoTokenFatalErrors = new LinkedList<String>();
    }

    @Override
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
            log.error(FAILED_TO_GET_CRYPTO_TOKEN_ + e.getMessage());
            throw new CryptoTokenOfflineException(e);
        }
    }

    @Override
    public boolean deactivateSigner() throws CryptoTokenOfflineException {
        if (log.isTraceEnabled()) {
            log.trace(">deactivateSigner");
        }
        
        try {
            final boolean result;
            final ICryptoToken token = getCryptoToken();
            if (token == null) {
        	if (log.isDebugEnabled()) {
                    log.debug("Crypto token not found");
        	}
        	result = false;
            } else {
                result = getCryptoToken().deactivate();
                if (log.isTraceEnabled()) {
                    log.trace("<deactivateSigner");
                }
            }
            return result;
        } catch (SignServerException e) {
            log.error(FAILED_TO_GET_CRYPTO_TOKEN_ + e.getMessage());
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
    @Override
    public String getAuthenticationType() {
        return config.getProperties().getProperty(WorkerConfig.PROPERTY_AUTHTYPE, IProcessable.AUTHTYPE_CLIENTCERT);
    }

    /**
     * Return the crypto token used by this instance.
     * If the crypto token has not yet been initialized, it will be instanciated before being returned.
     * 
     * @return The used crypto token
     * @throws SignServerException
     */
    public ICryptoToken getCryptoToken() throws SignServerException {
        if (log.isTraceEnabled()) {
            log.trace(">getCryptoToken");
        }
        final ICryptoToken result;
        if (cryptoToken == null) {
            // Check if a crypto token from an other worker is available
            final ICryptoToken tokenFromOtherWorker1 = getSignServerContext().getCryptoToken();
            final ICryptoToken tokenFromOtherWorker;

            // If it is a V2 crypto token we can wrap it and let this worker
            // decide which key to use. Otherwise the key is decided by the old
            // crypto token
            if (tokenFromOtherWorker1 instanceof ICryptoTokenV2) {
                tokenFromOtherWorker = new WrappedCryptoToken((ICryptoTokenV2) tokenFromOtherWorker1, config);
            } else {
                tokenFromOtherWorker = tokenFromOtherWorker1;
            }

            if (tokenFromOtherWorker != null) {
                result = tokenFromOtherWorker;
            } else {
                GlobalConfiguration gc = getGlobalConfigurationSession().getGlobalConfiguration();
                final Properties defaultProperties = new Properties();
                // TODO: The following could potentially be made generic
                String value = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL + DEFAULT_ + CryptoTokenHelper.PROPERTY_SHAREDLIBRARY);
                if (value != null) {
                    defaultProperties.setProperty(CryptoTokenHelper.PROPERTY_SHAREDLIBRARY, value);
                }
                value = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL + DEFAULT_ + CryptoTokenHelper.PROPERTY_SLOT);
                if (value != null) {
                    defaultProperties.setProperty(CryptoTokenHelper.PROPERTY_SLOT, value);
                }
                value = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL + DEFAULT_ + CryptoTokenHelper.PROPERTY_SLOTLISTINDEX);
                if (value != null) {
                    defaultProperties.setProperty(CryptoTokenHelper.PROPERTY_SLOTLISTINDEX, value);
                }
                value = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL + DEFAULT_ + CryptoTokenHelper.PROPERTY_ATTRIBUTESFILE);
                if (value != null) {
                    defaultProperties.setProperty(CryptoTokenHelper.PROPERTY_ATTRIBUTESFILE, value);
                }
                value = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL + DEFAULT_ + CryptoTokenHelper.PROPERTY_ATTRIBUTES);
                if (value != null) {
                    defaultProperties.setProperty(CryptoTokenHelper.PROPERTY_ATTRIBUTES, value);
                }
                value = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL + DEFAULT_ + CryptoTokenHelper.PROPERTY_PIN);
                if (value != null) {
                    defaultProperties.setProperty(CryptoTokenHelper.PROPERTY_PIN, value);
                }
                value = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL + DEFAULT_ + CryptoTokenHelper.PROPERTY_SLOTLABELTYPE);
                if (value != null) {
                    defaultProperties.setProperty(CryptoTokenHelper.PROPERTY_SLOTLABELTYPE, value);
                }
                value = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL + DEFAULT_ + CryptoTokenHelper.PROPERTY_SLOTLABELVALUE);
                if (value != null) {
                    defaultProperties.setProperty(CryptoTokenHelper.PROPERTY_SLOTLABELVALUE, value);
                }
                String className = null;
                try {
                    className = gc.getCryptoTokenProperty(workerId, GlobalConfiguration.CRYPTOTOKENPROPERTY_CLASSPATH);

                    if (log.isDebugEnabled()) {
                        log.debug("Found cryptotoken classpath: " + className);
                    }
                    if (className == null) {
                        result = null;
                    } else {
                        Class<?> implClass = Class.forName(className);
                        Object obj = implClass.newInstance();
                        cryptoToken = (ICryptoToken) obj;
                        Properties properties = new Properties();
                        properties.putAll(defaultProperties);
                        properties.putAll(config.getProperties());
                        cryptoToken.init(workerId, properties);
                        result = cryptoToken;
                    }
                } catch (CryptoTokenInitializationFailureException e) {
                    final StringBuilder sb = new StringBuilder();

                    if (log.isDebugEnabled()) {
                        log.debug("Failed to initialize crypto token: " + e.getMessage());
                    }

                    sb.append("Failed to initialize crypto token");

                    // collect cause messages
                    final List<String> causes = new LinkedList<String>();

                    causes.add(e.getMessage());

                    Throwable cause = e.getCause();

                    // iterate throug cause until we reach the bottom
                    while (cause != null) {
                        final String causeMessage = cause.getMessage();

                        if (log.isDebugEnabled()) {
                            log.debug("Cause: " + causeMessage);
                        }

                        // if cause message wasn't already seen, add it to the list
                        if (!causes.contains(causeMessage)) {
                            causes.add(causeMessage);
                        }

                        cause = cause.getCause();
                    }

                    // prepend cause messages with some separators at the tail of our message
                    for (final String causeMessage : causes) {
                        sb.append(": ");
                        sb.append(causeMessage);
                    }

                    final String error = sb.toString();

                    if (!cryptoTokenFatalErrors.contains(error)) {
                        cryptoTokenFatalErrors.add(error);
                    }
                    throw new SignServerException("Failed to initialize crypto token: " + e.getMessage(), e);
                } catch (ClassNotFoundException e) {
                    final String error = "Crypto token class not found: " + className;

                    if (!cryptoTokenFatalErrors.contains(error)) {
                        cryptoTokenFatalErrors.add(error);
                    }
                    throw new SignServerException("Class not found", e);
                } catch (IllegalAccessException iae) {
                    final String error = "Crypto token illegal access";

                    if (!cryptoTokenFatalErrors.contains(error)) {
                        cryptoTokenFatalErrors.add(error);
                    }
                    throw new SignServerException("Illegal access", iae);
                } catch (InstantiationException ie) {
                    final String error = "Crypto token instantiation error";

                    if (!cryptoTokenFatalErrors.contains(error)) {
                        cryptoTokenFatalErrors.add(error);
                    }
                    throw new SignServerException("Instantiation error", ie);
                }
            }
        } else {
            result = cryptoToken;
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCryptoToken: " + cryptoToken);
        }

        return result;
    }

    /**
     * Wrapper for crypto tokens so that workers can still use the old crypto
     * token V1 API. The wrapper delegates the operations on keys to the V2
     * API and using the keys defined in _this_ worker.
     */
    private static class WrappedCryptoToken implements ICryptoToken, ICryptoTokenV2 {

        /** Logger for this class. */
        private static final Logger LOG = Logger.getLogger(WrappedCryptoToken.class);

        private final ICryptoTokenV2 delegate;
        private final WorkerConfig config;

        /**
         * Constructs a new instance of the wrapped crypto token.
         * @param delegate The V2 implementation.
         * @param config This worker's configuration
         */
        public WrappedCryptoToken(ICryptoTokenV2 delegate, WorkerConfig config) {
            this.delegate = delegate;
            this.config = config;
        }

        @Override
        public void init(int workerId, Properties props) throws CryptoTokenInitializationFailureException {
            delegate.init(workerId, props);
        }

        @Override
        public int getCryptoTokenStatus() {
            return delegate.getCryptoTokenStatus();
        }

        @Override
        public void activate(String authenticationcode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
            delegate.activate(authenticationcode);
        }

        @Override
        public boolean deactivate() throws CryptoTokenOfflineException {
            return delegate.deactivate();
        }

        @Override
        public PrivateKey getPrivateKey(int purpose) throws CryptoTokenOfflineException {
            final String alias = purpose == ICryptoToken.PURPOSE_NEXTKEY ? config.getProperty(CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY) : config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY);
            return delegate.getPrivateKey(alias);
        }

        @Override
        public PublicKey getPublicKey(int purpose) throws CryptoTokenOfflineException {
            final String alias = purpose == ICryptoToken.PURPOSE_NEXTKEY ? config.getProperty(CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY) : config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY);
            return delegate.getPublicKey(alias);
        }

        @Override
        public String getProvider(int providerUsage) {
            return delegate.getProvider(providerUsage);
        }

        @Override
        public Certificate getCertificate(int purpose) throws CryptoTokenOfflineException {
            final String alias = purpose == ICryptoToken.PURPOSE_NEXTKEY ? config.getProperty(CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY) : config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY);
            return delegate.getCertificate(alias);
        }

        @Override
        public List<Certificate> getCertificateChain(int purpose) throws CryptoTokenOfflineException {
            final String alias = purpose == ICryptoToken.PURPOSE_NEXTKEY ? config.getProperty(CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY) : config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY);
            return delegate.getCertificateChain(alias);
        }

        @Override
        public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, boolean defaultKey) throws CryptoTokenOfflineException {
            return delegate.genCertificateRequest(info, explicitEccParameters, defaultKey ? config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY) : config.getProperty(CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY));
        }

        @Override
        public boolean destroyKey(int purpose) {
            boolean result = false;
            final String alias = purpose == ICryptoToken.PURPOSE_NEXTKEY ? config.getProperty(CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY) : config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY);
            try {
                result = delegate.removeKey(alias);
            } catch (CryptoTokenOfflineException ex) {
                LOG.error("Could not destroy key: " +ex.getMessage());
            } catch (KeyStoreException ex) {
                LOG.error("Could not destroy key: " +ex.getMessage());
            } catch (SignServerException ex) {
                LOG.error("Could not destroy key: " +ex.getMessage());
            }
            return result;
        }

        @Override
        public Collection<org.signserver.common.KeyTestResult> testKey(String alias, char[] authCode) throws CryptoTokenOfflineException, KeyStoreException {
            return delegate.testKey(alias, authCode);
        }

        @Override
        public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
            return delegate.getKeyStore();
        }

        @Override
        public PrivateKey getPrivateKey(String alias) throws CryptoTokenOfflineException {
            return delegate.getPrivateKey(alias);
        }

        @Override
        public PublicKey getPublicKey(String alias) throws CryptoTokenOfflineException {
            return delegate.getPublicKey(alias);
        }

        @Override
        public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, String keyAlias) throws CryptoTokenOfflineException {
            return delegate.genCertificateRequest(info, explicitEccParameters, keyAlias);
        }

        @Override
        public void generateKey(String keyAlgorithm, String keySpec, String alias, char[] authCode) throws CryptoTokenOfflineException, IllegalArgumentException {
            delegate.generateKey(keyAlgorithm, keySpec, alias, authCode);
        }

        @Override
        public boolean removeKey(String alias) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
            return delegate.removeKey(alias);
        }

        @Override
        public Certificate getCertificate(String alias) throws CryptoTokenOfflineException {
            return delegate.getCertificate(alias);
        }

        @Override
        public List<Certificate> getCertificateChain(String alias) throws CryptoTokenOfflineException {
            return delegate.getCertificateChain(alias);
        }

    };

    @Override
    public int getCryptoTokenStatus() {
        int result = WorkerStatus.STATUS_OFFLINE;
        try {
            ICryptoToken token = getCryptoToken();
            if (token != null) {
                result = token.getCryptoTokenStatus();
            }
        } catch (SignServerException e) {
            if (log.isTraceEnabled()) {
                log.trace("Could not get crypto token: " + e.getMessage(), e);
            }
        }
        return result;
    }

    /**
     * Method that returns the certificate used when signing
     * @throws CryptoTokenOfflineException 
     */
    public Certificate getSigningCertificate() throws CryptoTokenOfflineException {
        if (cert == null) {
            try {
                final ICryptoToken token = getCryptoToken();
                if (token != null) {
                    cert = (X509Certificate) token.getCertificate(ICryptoToken.PURPOSE_SIGN);
                }
            } catch (SignServerException e) {
                log.error(FAILED_TO_GET_CRYPTO_TOKEN_ + e.getMessage());
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
    public List<Certificate> getSigningCertificateChain() throws CryptoTokenOfflineException {
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
                log.error(FAILED_TO_GET_CRYPTO_TOKEN_ + e.getMessage());
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
            log.error(FAILED_TO_GET_CRYPTO_TOKEN_ + e.getMessage());
            throw new CryptoTokenOfflineException(e);
        }
    }

    /**
     * Method sending the removal request to the signtoken
     */
    @Override
    public boolean destroyKey(int purpose) {
        boolean result = false;
        try {
            result = getCryptoToken().destroyKey(purpose);
        } catch (SignServerException e) {
            log.error(FAILED_TO_GET_CRYPTO_TOKEN_ + e.getMessage());
        }
        return result;
    }
    
    @Override
    public boolean removeKey(String alias) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
        boolean result = false;
        ICryptoToken token = getCryptoToken();
        if (token == null) {
            throw new CryptoTokenOfflineException("Crypto token offline");
        } else if (token instanceof IKeyRemover) {
            result = ((IKeyRemover) token).removeKey(alias);
        } // Else key removal not supported by crypto token
        return result;
    }

    /**
     * @see IKeyGenerator#generateKey(java.lang.String, java.lang.String,
     * java.lang.String, char[])
     */
    @Override
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
            log.error(FAILED_TO_GET_CRYPTO_TOKEN_ + e.getMessage());
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
            log.error(FAILED_TO_GET_CRYPTO_TOKEN_ + e.getMessage());
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
    
    /**
     * Returns fatal errors found while initializing the crypto token.
     * 
     * @return List of crypto token error message strings
     */
    protected List<String> getCryptoTokenFatalErrors() {
        return cryptoTokenFatalErrors;
    }
}
