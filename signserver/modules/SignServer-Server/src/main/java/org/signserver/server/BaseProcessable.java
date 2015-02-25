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
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.*;
import org.signserver.server.aliasselectors.AliasSelector;
import org.signserver.server.aliasselectors.DefaultAliasSelector;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import org.signserver.server.cryptotokens.DefaultCryptoInstance;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.cryptotokens.IKeyGenerator;
import org.signserver.server.cryptotokens.IKeyRemover;
import org.signserver.server.cryptotokens.ICryptoTokenV2;
import org.signserver.server.cryptotokens.ICryptoTokenV3;
import org.signserver.server.cryptotokens.TokenSearchResults;

public abstract class BaseProcessable extends BaseWorker implements IProcessable, IKeyRemover {

    /** Log4j instance for actual implementation class */
    private final transient Logger log = Logger.getLogger(this.getClass());

    /** Property specifying if the private key object should be cached. */
    public static final String PROPERTY_CACHE_PRIVATEKEY = "CACHE_PRIVATEKEY";

    private static final String FAILED_TO_GET_CRYPTO_TOKEN_ = "Failed to get crypto token: ";
    private static final String FAILED_TO_GET_ALIAS_ = "Failed to get alias: ";
    private static final String DEFAULT_ = "DEFAULT.";

    protected ICryptoToken cryptoToken;

    private AliasSelector aliasSelector;

    private List<String> fatalErrors;
    
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
        fatalErrors = new LinkedList<String>();
        
        // initialize key alias selector
        final String aliasSelectorClass =
                config.getProperty(WorkerConfig.PROPERTY_ALIASSELECTOR);
        
        aliasSelector = createAliasSelector(aliasSelectorClass);
        
        if (aliasSelector != null) {
            aliasSelector.init(workerId, config, workerContext, workerEM);
        }
    }
    
    /**
     * Creates an instance of AliasSelector given the value set for the
     * ALIASSELECTOR worker property.
     * Signers can override this method to provide a custom default
     * implementation of an alias selector.
     * An implementation should set fatalErrors in case of failure.
     * 
     * @param aliasSelectorClassName The value of the ALIASSELECTOR property
     * @return An instance implementing AliasSelector, or null if in case of error
     */
    protected AliasSelector createAliasSelector(final String aliasSelectorClassName) {
        AliasSelector selector = null;
        
        if (aliasSelectorClassName == null) {
            selector = new DefaultAliasSelector();
        } else {
            try {
                final Class<?> implClass = Class.forName(aliasSelectorClassName);
                final Object instance = implClass.newInstance();
                
                selector = (AliasSelector) instance;
            } catch (ClassNotFoundException e) {
                fatalErrors.add("Alias selector class not found: " +
                                aliasSelectorClassName);
            } catch (InstantiationException e) {
                fatalErrors.add("Failed to instansiate alias selector: " +
                                e.getMessage());
            } catch (IllegalAccessException e) {
                fatalErrors.add("Failed to access alias selector class: " +
                                e.getMessage());
            }
        }
        
        return selector;
    }

    /**
     * Get alias given a specific purpose.
     * 
     * @param purpose
     * @param request
     * @param context
     * @return Key alias to use
     * @throws IllegalRequestException
     * @throws CryptoTokenOfflineException
     * @throws SignServerException
     */
    private String getAlias(final int purpose, final ProcessRequest request,
                            final RequestContext context)
            throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
       return aliasSelector.getAlias(purpose, this, request, context);
    }
    
    /**
     * Get private key for a signing request.
     * This will delegate to the alias selector if the crypto token implements
     * the new token API.
     * 
     * @param purpose
     * @param request
     * @param context
     * @return
     * @throws IllegalRequestException
     * @throws CryptoTokenOfflineException
     * @throws SignServerException 
     * @see #aquireCryptoInstance(java.lang.String, org.signserver.common.RequestContext) 
     * @deprecated Use aqcuireCryptoInstance and releaseCryptoInstance
     */
    @Deprecated
    protected PrivateKey getPrivateKey(final int purpose,
                                       final ProcessRequest request,
                                       final RequestContext context)
            throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        final ICryptoToken token = getCryptoToken();
        
        if (token instanceof ICryptoTokenV2) {
            final String alias =
                    aliasSelector.getAlias(purpose, this, request, context);

            return ((ICryptoTokenV2) token).getPrivateKey(alias);
        } else {
            return token.getPrivateKey(purpose);
        }
    }
    
    /**
     * Get public key for a signing request.
     * This will delegate to the alias selector if the crypto token implements
     * the new token API.
     * 
     * @param purpose
     * @param request
     * @param context
     * @return
     * @throws IllegalRequestException
     * @throws CryptoTokenOfflineException
     * @throws SignServerException 
     */
    protected PublicKey getPublicKey(final int purpose,
                                     final ProcessRequest request,
                                     final RequestContext context)
            throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        final ICryptoToken token = getCryptoToken();
        
        if (token instanceof ICryptoTokenV2) {
            final String alias =
                    aliasSelector.getAlias(purpose, this, request, context);
            
            return ((ICryptoTokenV2) token).getPublicKey(alias);
        } else {
            return token.getPublicKey(purpose);
        }
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
        if (cryptoToken == null) {
            // Check if a crypto token from an other worker is available
            final ICryptoToken tokenFromOtherWorker1 = getSignServerContext().getCryptoToken();
            final ICryptoToken tokenFromOtherWorker;

            // If it is a V2 or V3 crypto token we can wrap it and let this worker
            // decide which key to use. Otherwise the key is decided by the old
            // crypto token
            if (tokenFromOtherWorker1 instanceof ICryptoTokenV3) {
                tokenFromOtherWorker = new WrappedCryptoTokenV3((ICryptoTokenV3) tokenFromOtherWorker1, config);
            }
            else if (tokenFromOtherWorker1 instanceof ICryptoTokenV2) {
                tokenFromOtherWorker = new WrappedCryptoToken((ICryptoTokenV2) tokenFromOtherWorker1, config);
            } else {
                tokenFromOtherWorker = tokenFromOtherWorker1;
            }

            if (tokenFromOtherWorker != null) {
                cryptoToken = tokenFromOtherWorker;
            } else {
                GlobalConfiguration gc = getGlobalConfigurationSession().getGlobalConfiguration();
                final Properties defaultProperties = new Properties();
                // TODO: The following could potentially be made generic
                String value = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL + DEFAULT_ + CryptoTokenHelper.PROPERTY_SHAREDLIBRARY);
                if (value != null) {
                    defaultProperties.setProperty(CryptoTokenHelper.PROPERTY_SHAREDLIBRARY, value);
                }
                value = gc.getProperty(GlobalConfiguration.SCOPE_GLOBAL + DEFAULT_ + CryptoTokenHelper.PROPERTY_SHAREDLIBRARYNAME);
                if (value != null) {
                    defaultProperties.setProperty(CryptoTokenHelper.PROPERTY_SHAREDLIBRARYNAME, value);
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
                        cryptoToken = null;
                    } else {
                        Class<?> implClass = Class.forName(className);
                        Object obj = implClass.newInstance();
                        final ICryptoToken token = (ICryptoToken) obj;
                        Properties properties = new Properties();
                        properties.putAll(defaultProperties);
                        properties.putAll(config.getProperties());
                        token.init(workerId, properties);
                        cryptoToken = token;
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
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCryptoToken: " + cryptoToken);
        }

        return cryptoToken;
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

        private final boolean cachePrivateKey;
        private PrivateKey cachedPrivateKey;

        /**
         * Constructs a new instance of the wrapped crypto token.
         * @param delegate The V2 implementation.
         * @param config This worker's configuration
         */
        public WrappedCryptoToken(ICryptoTokenV2 delegate, WorkerConfig config) {
            this.delegate = delegate;
            this.config = config;
            cachePrivateKey = Boolean.parseBoolean(config.getProperty(PROPERTY_CACHE_PRIVATEKEY, Boolean.FALSE.toString()));
            if (LOG.isDebugEnabled()) {
                LOG.debug("cachePrivateKey: " + cachePrivateKey);
            }
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
            final PrivateKey result;
            if (purpose == ICryptoToken.PURPOSE_NEXTKEY) {
                result = delegate.getPrivateKey(config.getProperty(CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY));
            } else {
                if (cachePrivateKey && cachedPrivateKey != null) {
                    result = cachedPrivateKey;
                } else {
                    result = delegate.getPrivateKey(config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY));
                    if (cachePrivateKey) {
                        cachedPrivateKey = result;
                    }
                }
            }
            return result;
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

    private static class WrappedCryptoTokenV3 extends WrappedCryptoToken implements ICryptoTokenV3 {
        
        /** Logger for this class. */
        private static final Logger LOG = Logger.getLogger(WrappedCryptoTokenV3.class);

        private final ICryptoTokenV3 delegate;

        public WrappedCryptoTokenV3(ICryptoTokenV3 delegate, WorkerConfig config) {
            super(delegate, config);
            this.delegate = delegate;
        }
        
        @Override
        public void importCertificateChain(List<Certificate> certChain, String alias, char[] athenticationCode, IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
            delegate.importCertificateChain(certChain, alias, athenticationCode, services);
        }

        @Override
        public TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData, IServices services) throws CryptoTokenOfflineException, QueryException {
            return delegate.searchTokenEntries(startIndex, max, qc, includeData, services);
        }

        @Override
        public ICryptoInstance aquireCryptoInstance(String alias, RequestContext context) throws CryptoTokenOfflineException, IllegalRequestException, SignServerException {
            return delegate.aquireCryptoInstance(alias, context);
        }

        @Override
        public void releaseCryptoInstance(ICryptoInstance instance) {
            delegate.releaseCryptoInstance(instance);
        }

        @Override
        public void generateKey(String keyAlgorithm, String keySpec, String alias, char[] authCode, IServices services) throws CryptoTokenOfflineException, IllegalArgumentException {
            delegate.generateKey(keyAlgorithm, keySpec, alias, authCode, services);
        }

        @Override
        public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException {
            return delegate.genCertificateRequest(info, explicitEccParameters, keyAlias, services);
        }
        
    }

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
     * Method that returns the certificate used when signing.
     * If the worker has a configured certificate this is returned.
     * Otherwise a certificate from the crypto token is returned,
     * based on the request and request context depending on which alias selector
     * is configured.
     * 
     * @param request Signing request
     * @param context Request context
     * @return Signing certificate
     * @throws CryptoTokenOfflineException
     * @deprecated Use getSigningCertificate(ICryptoInstance)
     */
    @Deprecated
    public Certificate getSigningCertificate(final ProcessRequest request,
                                             final RequestContext context)
            throws CryptoTokenOfflineException {
        
        Certificate cert =
                (new ProcessableConfig(config)).getSignerCertificate();
        
        if (cert == null) {
            final ICryptoToken token;
            
            try {
                token = getCryptoToken();
            } catch (SignServerException e) {
                log.error(FAILED_TO_GET_CRYPTO_TOKEN_ + e.getMessage());
                throw new CryptoTokenOfflineException(e);
            }
            
            if (token != null) {
                if (token instanceof ICryptoTokenV2) {
                    final ICryptoTokenV2 tokenV2 =
                            (ICryptoTokenV2) token;
                    
                    try {
                        final String alias =
                            getAlias(ICryptoToken.PURPOSE_SIGN, request, context);
                    
                        cert = tokenV2.getCertificate(alias);
                    } catch (IllegalRequestException e) {
                        log.error(FAILED_TO_GET_ALIAS_ + e.getMessage());
                        throw new CryptoTokenOfflineException(e);
                    } catch (SignServerException e) {
                        log.error(FAILED_TO_GET_ALIAS_ + e.getMessage());
                        throw new CryptoTokenOfflineException(e);
                    }
                } else {
                    cert = token.getCertificate(ICryptoToken.PURPOSE_SIGN);
                }
            }
        }
        
        return cert;
    }

    /**
     * Method that returns the certificate used when signing.
     * If the worker has a configured certificate this is returned.
     * Otherwise a certificate from the crypto token is returned.
     * 
     * @param crypto instance to get certificate from in case there is non in config
     * @return Signing certificate
     * @throws CryptoTokenOfflineException
     */
    public Certificate getSigningCertificate(ICryptoInstance crypto) throws CryptoTokenOfflineException {
        final Certificate result;
        final Certificate certFromConfig = (new ProcessableConfig(config)).getSignerCertificate();
        if (certFromConfig == null) {
            result = crypto.getCertificate();
        } else {
            result = certFromConfig;
        }
        return result;
    }
    
    /**
     * Method that returns the certificate used when signing.
     * If the worker has a configured certificate this is returned.
     * Otherwise a certificate from the crypto token is returned.
     * This method is called with no signing request and context and assumes
     * an alias selector having a default behavior for this.
     * 
     * @return Signing certificate
     * @throws CryptoTokenOfflineException 
     */
    @Deprecated
    public Certificate getSigningCertificate() throws CryptoTokenOfflineException {
        return getSigningCertificate(null, null);
    }

    /**
     * 
     * @param alias
     * @return
     * @throws CryptoTokenOfflineException 
     * @deprecated Use getSigningCertificateChain(ICryptoInstance)
     */
    @Deprecated
    public List<Certificate> getSigningCertificateChain(final String alias)
            throws CryptoTokenOfflineException {
        final ICryptoToken token;
        List<Certificate> ret = null;
        
        try {
            token = getCryptoToken();
        } catch (SignServerException e) {
            log.error(FAILED_TO_GET_CRYPTO_TOKEN_ + e.getMessage());
            throw new CryptoTokenOfflineException(e);
        }

        if (token != null) {
            if (token instanceof ICryptoTokenV2) {
                ret = ((ICryptoTokenV2) token).getCertificateChain(alias);
            }
        }
        
        return ret;
    }
    
    /**
     * Method that returns the certificate chain used when signing.
     * If the worker has a configured certificate chain this is returned.
     * Otherwise a certificate chain from the crypto token is returned,
     * based on the request and request context depending on which alias selector
     * is configured.
     * 
     * @param request Signing request
     * @param context Request context
     * @return The certificate chain used for signing
     * @throws CryptoTokenOfflineException
     * @deprecated Use getSigningCertificateChain(ICryptoInstance)
     */
    @Deprecated
    public List<Certificate> getSigningCertificateChain(final ProcessRequest request,
                                                        final RequestContext context)
            throws CryptoTokenOfflineException {
        List<Certificate> certChain =
                (new ProcessableConfig(config)).getSignerCertificateChain();
        
        if (certChain == null) {
            final ICryptoToken token;
            
            try {
                token = getCryptoToken();
            } catch (SignServerException e) {
                log.error(FAILED_TO_GET_CRYPTO_TOKEN_ + e.getMessage());
                throw new CryptoTokenOfflineException(e);
            }
            
            if (token != null) {
                if (token instanceof ICryptoTokenV2) {
                    final ICryptoTokenV2 tokenV2 =
                            (ICryptoTokenV2) token;
                    
                    try {
                        final String alias =
                            getAlias(ICryptoToken.PURPOSE_SIGN, request, context);
                    
                        certChain = tokenV2.getCertificateChain(alias);
                    } catch (IllegalRequestException e) {
                        log.error(FAILED_TO_GET_ALIAS_ + e.getMessage());
                        throw new CryptoTokenOfflineException(e);
                    } catch (SignServerException e) {
                        log.error(FAILED_TO_GET_ALIAS_ + e.getMessage());
                        throw new CryptoTokenOfflineException(e);
                    }
                } else {
                    certChain = token.getCertificateChain(ICryptoToken.PURPOSE_SIGN);
                }
            }
        }
        
        return certChain;
    }

    /**
     * Method that returns the certificate chain used when signing.
     * If the worker has a configured certificate chain this is returned.
     * Otherwise a certificate chain from the crypto token is returned.
     * This method is called with no signing request and context and assumes
     * an alias selector having a default behavior for this.
     * 
     * @return Signing certificate chain
     * @throws CryptoTokenOfflineException 
     * @deprecated Use getSigningCertificateChain(ICryptoInstance)
     */
    @Deprecated
    public List<Certificate> getSigningCertificateChain() throws CryptoTokenOfflineException {
        return getSigningCertificateChain(null, null);
    }

    
    /**
     * Method that returns the certificate chain used when signing.
     * If the worker has a configured certificate chain this is returned.
     * Otherwise a certificate chain from the crypto token is returned.
     * 
     * @param crypto instance to get chain from unless it is not available in config
     * @return The certificate chain used for signing
     */
    public List<Certificate> getSigningCertificateChain(final ICryptoInstance crypto) {
        final List<Certificate> result;
        final List<Certificate> certChainFromConfig = config == null ? null : (new ProcessableConfig(config)).getSignerCertificateChain();
        if (certChainFromConfig == null) {
            result = crypto.getCertificateChain();
        } else {
            result = certChainFromConfig;
        }
        return result;
    }

    public ICertReqData genCertificateRequest(ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException {
        return genCertificateRequest(certReqInfo, explicitEccParameters, keyAlias, explicitEccParameters, services);
    }

    public ICertReqData genCertificateRequest(ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, boolean defaultKey, IServices services) throws CryptoTokenOfflineException {
        return genCertificateRequest(certReqInfo, explicitEccParameters, null, defaultKey, services);
    }

    /**
     * Method sending the request info to the signtoken
     * @return the request or null if method isn't supported by signertoken.
     */
    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            final boolean explicitEccParameters, final boolean defaultKey)
            throws CryptoTokenOfflineException {
        return genCertificateRequest(info, explicitEccParameters, null,
                defaultKey, new ServicesImpl());
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            boolean explicitEccParameters, String keyAlias)
            throws CryptoTokenOfflineException {
        return genCertificateRequest(info, explicitEccParameters, keyAlias,
                false, new ServicesImpl());
    }
    
    private ICertReqData genCertificateRequest(final ISignerCertReqInfo info,
            final boolean explicitEccParameters, final String keyAlias,
            final boolean defaultKey, final IServices services)
            throws CryptoTokenOfflineException {
        if (log.isTraceEnabled()) {
            log.trace(">genCertificateRequest");
        }
        
        try {
            final ICryptoToken token = getCryptoToken();
            if (log.isDebugEnabled()) {
                log.debug("Found a crypto token of type: " + token.getClass().getName());
                log.debug("Token status is: " + token.getCryptoTokenStatus());
            }
            
            final ICertReqData data;
            
            if (keyAlias != null) {
                if (token instanceof ICryptoTokenV3) {
                    final ICryptoTokenV3 tokenV3 = (ICryptoTokenV3) token;
                    
                    data = tokenV3.genCertificateRequest(info,
                                                         explicitEccParameters,
                                                         keyAlias,
                                                         services);
                } else if (token instanceof ICryptoTokenV2) {
                    final ICryptoTokenV2 tokenV2 = (ICryptoTokenV2) token;
                    
                    data = tokenV2.genCertificateRequest(info,
                                                         explicitEccParameters,
                                                         keyAlias);
                } else {
                    throw new CryptoTokenOfflineException("Crypto token doesn't support generating certificate request with key alias");
                }
            } else {
                data = token.genCertificateRequest(info,
                    explicitEccParameters, defaultKey);
            }

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
        generateKey(keyAlgorithm, keySpec, alias, authCode, new ServicesImpl());
    }
    
    public void generateKey(final String keyAlgorithm, final String keySpec,
            final String alias, final char[] authCode, final IServices services)
            throws CryptoTokenOfflineException, IllegalArgumentException {
        try {
            ICryptoToken token = getCryptoToken();
            if (token == null) {
                throw new CryptoTokenOfflineException("Crypto token offline");
            } else if (token instanceof ICryptoTokenV3) {
                ((ICryptoTokenV3) token).generateKey(keyAlgorithm, keySpec, alias,
                        authCode, services);
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
   
    @Override
    public void importCertificateChain(final List<Certificate> certChain,
                                       final String alias,
                                       final char[] authenticationCode,
                                       final IServices services)
            throws CryptoTokenOfflineException, OperationUnsupportedException {
        try {
            final ICryptoToken token = getCryptoToken();
            
            if (token == null) {
                throw new CryptoTokenOfflineException("Crypto token offline");
            }
            
            if (token instanceof ICryptoTokenV3) {
                final ICryptoTokenV3 tokenV3 = (ICryptoTokenV3) token;
                
                tokenV3.importCertificateChain(certChain, alias, authenticationCode, services);
            } else {
                throw new OperationUnsupportedException("Importing certificate chain is not supported by crypto token");
            }
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

    @Override
    protected List<String> getFatalErrors() {
        final List<String> errors = new LinkedList<String>();

        errors.addAll(super.getFatalErrors());
        errors.addAll(fatalErrors);
        errors.addAll(aliasSelector.getFatalErrors());
        
        return errors;
    }
 
    /**
     * Aquire a crypto instance in order to perform crypto operations during
     * a limited scope.
     * 
     * It is the caller's responsibility to make sure the call is followed up
     * by a call to releaseCryptoInstance() for each instance. Use try-final.
     * 
     * @param context the request context
     * @return an crypto instance
     * @throws CryptoTokenOfflineException
     * @throws IllegalRequestException
     * @throws SignServerException 
     */
    protected ICryptoInstance aquireCryptoInstance(final int purpose, final ProcessRequest request, final RequestContext context) throws SignServerException, CryptoTokenOfflineException, IllegalRequestException {
        final ICryptoInstance result;
        final String alias = aliasSelector.getAlias(purpose, this, request, context);
        ICryptoToken token = getCryptoToken();
        if (token instanceof ICryptoTokenV3) {
            // Great this is V3 (3.7)
            ICryptoTokenV3 token3 = (ICryptoTokenV3) token;
            result = token3.aquireCryptoInstance(alias, context);
        } else if (token instanceof ICryptoTokenV2) {
            // Backwards compatibility for old V2 tokens (3.6)
            ICryptoTokenV2 token2 = (ICryptoTokenV2) token;
            PrivateKey privateKey = token2.getPrivateKey(alias);
            Provider provider = Security.getProvider(token2.getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
            result = new DefaultCryptoInstance(alias, context, provider, privateKey, token2.getCertificateChain(alias));
        } else {
            // V1 (<3.6) does not support aliases so not much we can do
            throw new SignServerException("Operation not supported by crypto token");
        }
        return result;
    }

    /**
     * Releases a previously acquired crypto instance.
     * @param instance to release
     */
    protected void releaseCryptoInstance(final ICryptoInstance instance) throws SignServerException {
        ICryptoToken token = getCryptoToken();
        if (token instanceof ICryptoTokenV3) {
            ((ICryptoTokenV3) token).releaseCryptoInstance(instance);
        }
    }
    
}
