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
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.*;
import org.signserver.server.aliasselectors.AliasSelector;
import org.signserver.server.aliasselectors.DefaultAliasSelector;
import org.signserver.server.cryptotokens.CryptoInstances;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import org.signserver.common.DuplicateAliasException;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.common.NoSuchAliasException;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;

public abstract class BaseProcessable extends BaseWorker implements IProcessable {

    /** Log4j instance for actual implementation class */
    private final transient Logger log = Logger.getLogger(this.getClass());

    /** Property specifying if the private key object should be cached. */
    public static final String PROPERTY_CACHE_PRIVATEKEY = "CACHE_PRIVATEKEY";

    private static final String FAILED_TO_GET_CRYPTO_TOKEN_ = "Failed to get crypto token: ";
    private static final String FAILED_TO_GET_ALIAS_ = "Failed to get alias: ";
    private static final String DEFAULT_ = "DEFAULT.";

    protected ICryptoTokenV4 cryptoToken;

    private AliasSelector aliasSelector;

    private List<String> fatalErrors;
    
    private boolean cachePrivateKey;
    private final Map<String, Object> workerCache = new HashMap<String, Object>(5);
    
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
        
        cachePrivateKey = Boolean.parseBoolean(config.getProperty(PROPERTY_CACHE_PRIVATEKEY, Boolean.FALSE.toString()));
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
     * Get alias given a specific purpose and as a side-effect log the chosen
     * alias in the context (if any).
     * 
     * @param purpose
     * @param request
     * @param context
     * @return Key alias to use
     * @throws IllegalRequestException
     * @throws CryptoTokenOfflineException
     * @throws SignServerException
     */
    private String getAliasAndLog(final int purpose, final ProcessRequest request,
                            final RequestContext context)
            throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        final String alias = aliasSelector.getAlias(purpose, this, request, context);
        
        if (context != null) {
            LogMap.getInstance(context).put(IWorkerLogger.LOG_KEYALIAS, alias);
            LogMap.getInstance(context).put(IWorkerLogger.LOG_CRYPTOTOKEN, getCryptoToken(workerId, config));
        }
        
        return alias;
    }
    
    /**
     * Get the name of the configured crypto token or if none, the name or
     * ID of the current worker.
     * @param workerId of the worker
     * @param config for the worker
     * @return name of crypto token or the worker name or id
     */
    private static String getCryptoToken(final int workerId, final WorkerConfig config) {
        String result = config.getProperty("CRYPTOTOKEN");
        if (result == null) {
            result = config.getProperty("NAME");
            if (result == null) {
                result = String.valueOf(workerId);
            }
        }
        return result;
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
    // TODO: Deprecate this method in 3.7
    /*protected PublicKey getPublicKey(final int purpose,
                                     final ProcessRequest request,
                                     final RequestContext context)
            throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        final ICryptoToken token = getCryptoToken();
        
        if (token instanceof ICryptoTokenV2) {
            final String alias = getAliasAndLog(purpose, request, context);
            
            return ((ICryptoTokenV2) token).getPublicKey(alias);
        } else {
            return token.getPublicKey(purpose);
        }
    }*/
    
    @Override
    public void activateSigner(String authenticationCode, IServices services)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException {
        if (log.isTraceEnabled()) {
            log.trace(">activateSigner");
        }
        
        try {
            ICryptoTokenV4 token = getCryptoToken();
        
            if (token == null) {
        	if (log.isDebugEnabled()) {
        		log.debug("Crypto token not found");
        	}
        	return;
            }
            token.activate(authenticationCode, services);
            
            // Check if certificate matches key
            final Certificate certFromConfig = (new ProcessableConfig(config)).getSignerCertificate();
            if (certFromConfig == null) {
                log.info("Activate: Signer " + workerId + ": No certificate in config");
            } else {
                RequestContext context = new RequestContext(true);
                context.setServices(services);
                ICryptoInstance instance = null;
                try {
                    instance = acquireDefaultCryptoInstance(context);
                    if (Arrays.equals(certFromConfig.getPublicKey().getEncoded(),
                        instance.getCertificate().getEncoded())) {
                        log.info("Activate: Signer " + workerId
                            + ": Certificate matches key");
                    } else {
                        log.info("Activate: Signer " + workerId
                            + ": Certificate does not match key");
                    }
                } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException | CertificateEncodingException ex) {
                    log.info("Unable to acquire crypto instance to check certificate: " + ex.getMessage(), ex);
                } finally {
                    if (instance != null) {
                        releaseCryptoInstance(instance, context);
                    }
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
    public boolean deactivateSigner(IServices services) throws CryptoTokenOfflineException {
        if (log.isTraceEnabled()) {
            log.trace(">deactivateSigner");
        }
        
        try {
            final boolean result;
            final ICryptoTokenV4 token = getCryptoToken();
            if (token == null) {
        	if (log.isDebugEnabled()) {
                    log.debug("Crypto token not found");
        	}
        	result = false;
            } else {
                result = getCryptoToken().deactivate(services);
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
    public ICryptoTokenV4 getCryptoToken() throws SignServerException {
        if (log.isTraceEnabled()) {
            log.trace(">getCryptoToken");
        }
        if (cryptoToken == null) {
            // Check if a crypto token from an other worker is available
            final ICryptoTokenV4 tokenFromOtherWorker1 = getSignServerContext().getCryptoToken();

            if (tokenFromOtherWorker1 != null) {
                cryptoToken = new WrappedCryptoToken(tokenFromOtherWorker1, config);
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
                    className = config.getCryptoTokenImplementationClass();
                    if (log.isDebugEnabled()) {
                        log.debug("Found cryptotoken class name: " + className);
                    }
                    if (className == null) {
                        cryptoToken = null;
                    } else {
                        Class<?> implClass = Class.forName(className);
                        Object obj = implClass.newInstance();
                        final ICryptoTokenV4 token = (ICryptoTokenV4) obj;
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

                    // prepend cause messages with some separators at the tail of our message
                    for (final String causeMessage : ExceptionUtil.getCauseMessages(e)) {
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
     * TODO: This is not needed anymore?
     */
    private static class WrappedCryptoToken implements ICryptoTokenV4 {

        /** Logger for this class. */
        private static final Logger LOG = Logger.getLogger(WrappedCryptoToken.class);

        private final ICryptoTokenV4 delegate;
        private final WorkerConfig config;

        /**
         * Constructs a new instance of the wrapped crypto token.
         * @param delegate The V2 implementation.
         * @param config This worker's configuration
         */
        public WrappedCryptoToken(ICryptoTokenV4 delegate, WorkerConfig config) {
            this.delegate = delegate;
            this.config = config;
        }

        @Override
        public void init(int workerId, Properties props) throws CryptoTokenInitializationFailureException {
            delegate.init(workerId, props);
        }

        @Override
        public void activate(String authenticationcode, IServices services) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
            delegate.activate(authenticationcode, services);
        }

        @Override
        public boolean deactivate(IServices services) throws CryptoTokenOfflineException {
            return delegate.deactivate(services);
        }

        @Override
        public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
            return delegate.getKeyStore();
        }

        @Override
        public int getCryptoTokenStatus(IServices services) {
            return delegate.getCryptoTokenStatus(services);
        }

        @Override
        public void importCertificateChain(List<Certificate> certChain, String alias, char[] athenticationCode, Map<String, Object> params, IServices services) throws TokenOutOfSpaceException, CryptoTokenOfflineException, NoSuchAliasException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
            delegate.importCertificateChain(certChain, alias, athenticationCode, params, services);
        }

        @Override
        public TokenSearchResults searchTokenEntries(int startIndex, int max, QueryCriteria qc, boolean includeData, Map<String, Object> params, IServices services) throws CryptoTokenOfflineException, QueryException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
            return delegate.searchTokenEntries(startIndex, max, qc, includeData, params, services);
        }

        @Override
        public ICryptoInstance acquireCryptoInstance(String alias, Map<String, Object> params, RequestContext context) throws CryptoTokenOfflineException, NoSuchAliasException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter, IllegalRequestException {
            return delegate.acquireCryptoInstance(alias, params, context);
        }

        @Override
        public void releaseCryptoInstance(ICryptoInstance instance, RequestContext context) {
            delegate.releaseCryptoInstance(instance, context);
        }

        @Override
        public void generateKey(String keyAlgorithm, String keySpec, String alias, char[] authCode, Map<String, Object> params, IServices services) throws TokenOutOfSpaceException, CryptoTokenOfflineException, DuplicateAliasException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
            delegate.generateKey(keyAlgorithm, keySpec, alias, authCode, params, services);
        }

        @Override
        public ICertReqData genCertificateRequest(ISignerCertReqInfo info, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException, NoSuchAliasException {
            return delegate.genCertificateRequest(info, explicitEccParameters, keyAlias, services);
        }

        @Override
        public Collection<org.signserver.common.KeyTestResult> testKey(String alias, char[] authCode, IServices Services) throws CryptoTokenOfflineException, KeyStoreException {
            return delegate.testKey(alias, authCode, Services);
        }

        @Override
        public boolean removeKey(String alias, IServices services) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
            return delegate.removeKey(alias, services);
        }

    };

    @Override
    public int getCryptoTokenStatus(IServices services) {
        int result = WorkerStatus.STATUS_OFFLINE;
        try {
            ICryptoTokenV4 token = getCryptoToken();
            if (token != null) {
                result = token.getCryptoTokenStatus(services);
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
     * Otherwise a certificate from the crypto token is returned.
     * 
     * @param crypto instance to get certificate from in case there is non in config
     * @return Signing certificate
     * @throws CryptoTokenOfflineException
     */
    public Certificate getSigningCertificate(ICryptoInstance crypto) throws CryptoTokenOfflineException {
        final Certificate result;
        final Certificate certFromConfig = (new ProcessableConfig(config)).getSignerCertificate();
        if (certFromConfig == null && crypto != null) {
            result = crypto.getCertificate();
        } else {
            result = certFromConfig;
        }
        return result;
    }
    
    public Certificate getSigningCertificate(IServices services) throws CryptoTokenOfflineException {
        return getSigningCertificate(config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY), services);
    }
    
    public Certificate getSigningCertificate(String alias, IServices services) throws CryptoTokenOfflineException {
        final Certificate result;
        final Certificate certFromConfig;
        if (alias != null) {
            certFromConfig = null;
        } else {
            certFromConfig = (new ProcessableConfig(config)).getSignerCertificate();
        }
        if (certFromConfig == null) {
            RequestContext context = new RequestContext(true);
            context.setServices(services);
            ICryptoInstance crypto = null;
            try {
                crypto = acquireDefaultCryptoInstance(alias, context);
                result = crypto.getCertificate();
            } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException | SignServerException ex) {
                throw new CryptoTokenOfflineException("Unable to get certificate from token: " + ex.getLocalizedMessage(), ex);
            } finally {
                if (crypto != null) {
                    try {
                        releaseCryptoInstance(crypto, context);
                    } catch (SignServerException ex) {
                        log.warn("Unable to release crypto instance", ex);
                    }
                }
            }
        } else {
            result = certFromConfig;
        }
        return result;
    }
    

    /**
     * Method that returns the certificate chain used when signing.
     * If the worker has a configured certificate chain this is returned.
     * Otherwise a certificate chain from the crypto token is returned.
     * 
     * @param crypto instance to get chain from unless it is not available in config or null to not check in the token
     * @return The certificate chain used for signing
     */
    public List<Certificate> getSigningCertificateChain(final ICryptoInstance crypto) {
        final List<Certificate> result;
        final List<Certificate> certChainFromConfig = config == null ? null : (new ProcessableConfig(config)).getSignerCertificateChain();
        if (certChainFromConfig == null && crypto != null) {
            result = crypto.getCertificateChain();
        } else {
            result = certChainFromConfig;
        }
        return result;
    }
    
    public List<Certificate> getSigningCertificateChain(final IServices services) throws CryptoTokenOfflineException {
        return getSigningCertificateChain(config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY), services);
    }
    
    public List<Certificate> getSigningCertificateChain(final String alias, final IServices services) throws CryptoTokenOfflineException {
        final List<Certificate> result;
        final List<Certificate> certChainFromConfig;
        if (alias != null) {
            certChainFromConfig = null;
        } else {
            certChainFromConfig = config == null ? null : (new ProcessableConfig(config)).getSignerCertificateChain();
        }
        if (certChainFromConfig == null) {
            RequestContext context = new RequestContext(true);
            context.setServices(services);
            ICryptoInstance crypto = null;
            try {
                crypto = acquireDefaultCryptoInstance(alias, context);
                result = crypto.getCertificateChain();
            } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter | IllegalRequestException | SignServerException ex) {
                throw new CryptoTokenOfflineException("Unable to get certificate chain from token: " + ex.getLocalizedMessage(), ex);
            } finally {
                if (crypto != null) {
                    try {
                        releaseCryptoInstance(crypto, context);
                    } catch (SignServerException ex) {
                        log.warn("Unable to release crypto instance", ex);
                    }
                }
            }
        } else {
            result = certChainFromConfig;
        }
        return result;
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, String keyAlias, IServices services) throws CryptoTokenOfflineException, NoSuchAliasException {
        return genCertificateRequest(certReqInfo, explicitEccParameters, keyAlias, explicitEccParameters, services);
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo certReqInfo, boolean explicitEccParameters, boolean defaultKey, IServices services) throws CryptoTokenOfflineException, NoSuchAliasException {
        return genCertificateRequest(certReqInfo, explicitEccParameters, null, defaultKey, services);
    }

    /**
     * Method sending the request info to the signtoken
     * @return the request or null if method isn't supported by signertoken.
     */
    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            final boolean explicitEccParameters, final boolean defaultKey)
            throws CryptoTokenOfflineException, NoSuchAliasException {
        return genCertificateRequest(info, explicitEccParameters, null,
                defaultKey, new ServicesImpl());
    }

    @Override
    public ICertReqData genCertificateRequest(ISignerCertReqInfo info,
            boolean explicitEccParameters, String keyAlias)
            throws CryptoTokenOfflineException, NoSuchAliasException {
        return genCertificateRequest(info, explicitEccParameters, keyAlias,
                false, new ServicesImpl());
    }
    
    private ICertReqData genCertificateRequest(final ISignerCertReqInfo info,
            final boolean explicitEccParameters, final String keyAlias,
            final boolean defaultKey, final IServices services)
            throws CryptoTokenOfflineException, NoSuchAliasException {
        if (log.isTraceEnabled()) {
            log.trace(">genCertificateRequest");
        }
        
        try {
            final ICryptoTokenV4 token = getCryptoToken();
            
            if (token == null) {
                throw new CryptoTokenOfflineException("Crypto token offline");
            }
            
            if (log.isDebugEnabled()) {
                log.debug("Found a crypto token of type: " + token.getClass().getName());
            }
            
            final ICertReqData data;
            
            if (keyAlias != null) {
                
                    data = token.genCertificateRequest(info,
                                                         explicitEccParameters,
                                                         keyAlias,
                                                         services);
            } else {
                data = token.genCertificateRequest(info,
                    explicitEccParameters, defaultKey ? config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY) : config.getProperty(CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY), services);
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

    @Override
    public boolean removeKey(String alias, IServices services) throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
        boolean result = false;
        ICryptoTokenV4 token = getCryptoToken();
        if (token == null) {
            throw new CryptoTokenOfflineException("Crypto token offline");
        } else {
            result = token.removeKey(alias, services);
        }
        return result;
    }
    
    @Override
    public void generateKey(final String keyAlgorithm, final String keySpec, final String alias, final char[] authCode, Map<String, Object> params, final IServices services) throws
            CryptoTokenOfflineException,
            DuplicateAliasException, 
            NoSuchAlgorithmException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter {
        try {
            ICryptoTokenV4 token = getCryptoToken();
            if (token == null) {
                throw new CryptoTokenOfflineException("Crypto token offline");
            } else {
                token.generateKey(keyAlgorithm, keySpec, alias, authCode, params, services);
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
        return testKey(alias, authCode, new ServicesImpl());
    }
    
    @Override
    public Collection<org.signserver.common.KeyTestResult> testKey(String alias,
        char[] authCode, IServices services) throws CryptoTokenOfflineException, KeyStoreException {
        try {
            ICryptoTokenV4 token = getCryptoToken();
            
            if (token == null) {
                throw new CryptoTokenOfflineException("Crypto token offline");
            } else {
                return token.testKey(alias, authCode, services);
            }
        } catch (SignServerException e) {
            log.error(FAILED_TO_GET_CRYPTO_TOKEN_ + e.getMessage());
            throw new CryptoTokenOfflineException(e);
        }
    }
   
    @Override
    public void importCertificateChain(final List<Certificate> certChain, final String alias, final char[] authenticationCode, Map<String, Object> params, final IServices services) throws
            CryptoTokenOfflineException,
            NoSuchAliasException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            OperationUnsupportedException {
        try {
            final ICryptoTokenV4 token = getCryptoToken();
            
            if (token == null) {
                throw new CryptoTokenOfflineException("Crypto token offline");
            } else {
                token.importCertificateChain(certChain, alias, authenticationCode, params, services);
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
    protected List<String> getCryptoTokenFatalErrors(IServices services) {
        return cryptoTokenFatalErrors;
    }

    @Override
    protected List<String> getFatalErrors(IServices services) {
        final List<String> errors = new LinkedList<>();

        errors.addAll(super.getFatalErrors(services));
        errors.addAll(fatalErrors);
        errors.addAll(aliasSelector.getFatalErrors());
        
        return errors;
    }
 
    /**
     * Acquire a crypto instance in order to perform crypto operations during
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
    protected ICryptoInstance acquireCryptoInstance(final int purpose, final ProcessRequest request, final RequestContext context) throws SignServerException, CryptoTokenOfflineException, IllegalRequestException {
        try {
            return acquireCryptoInstance(purpose, request, Collections.<String, Object>emptyMap(), context);
        } catch (UnsupportedCryptoTokenParameter ex) {
            throw new SignServerException("Empty list of parameters not supported by crypto token", ex);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new SignServerException("Empty list of parameters reported as invalid by crypto token", ex);
        }
    }
    
    /**
     * Acquire a crypto instance in order to perform crypto operations during
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
    protected ICryptoInstance acquireCryptoInstance(final int purpose, final ProcessRequest request, final Map<String, Object> params, final RequestContext context) throws SignServerException, CryptoTokenOfflineException, IllegalRequestException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
        final ICryptoInstance result;
        final String alias = getAliasAndLog(purpose, request, context);
        ICryptoTokenV4 token = getCryptoToken();
        if (token == null) {
            throw new CryptoTokenOfflineException("Crypto token not available");
        } 
        try {
            // Add our params with caching support
            final HashMap<String, Object> newParams = new HashMap<>(params);
            // Add a per-worker instance cache
            newParams.put(ICryptoTokenV4.PARAM_WORKERCACHE, workerCache);
            // Request caching for the default key only
            newParams.put(ICryptoTokenV4.PARAM_CACHEPRIVATEKEY, cachePrivateKey && alias != null && alias.equals(config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY)));

            result = token.acquireCryptoInstance(alias, newParams, context);
        } catch (NoSuchAliasException ex) {
            throw new CryptoTokenOfflineException("Key not available: " + ex.getMessage());
        }
        
        // Register the new instance
        CryptoInstances.getInstance(context).add(result);

        return result;
    }
    
    protected ICryptoInstance acquireDefaultCryptoInstance(RequestContext context) throws CryptoTokenOfflineException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter, IllegalRequestException, SignServerException {
        final ICryptoInstance result;
        String alias = config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY);
        
        ICryptoTokenV4 token = getCryptoToken();
        if (token == null) {
            throw new CryptoTokenOfflineException("Crypto token not available");
        } 
        try {
            result = token.acquireCryptoInstance(alias, Collections.<String, Object>emptyMap(), context);
        } catch (NoSuchAliasException ex) {
            throw new CryptoTokenOfflineException("Key not available: " + ex.getMessage());
        }
        
        // Register the new instance
        CryptoInstances.getInstance(context).add(result);

        return result;
    }
    
    // XXX: Should not be needed, XXX: Mostly duplicated
    protected ICryptoInstance acquireDefaultCryptoInstance(String alias, RequestContext context) throws CryptoTokenOfflineException, InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter, IllegalRequestException, SignServerException {
        final ICryptoInstance result;

        ICryptoTokenV4 token = getCryptoToken();
        if (token == null) {
            throw new CryptoTokenOfflineException("Crypto token not available");
        } 
        try {
            result = token.acquireCryptoInstance(alias, Collections.<String, Object>emptyMap(), context);
        } catch (NoSuchAliasException ex) {
            throw new CryptoTokenOfflineException("Key not available: " + ex.getMessage());
        }
        
        // Register the new instance
        CryptoInstances.getInstance(context).add(result);

        return result;
    }

    /**
     * Releases a previously acquired crypto instance.
     * @param instance to release
     */
    protected void releaseCryptoInstance(final ICryptoInstance instance, RequestContext context) throws SignServerException {
        ICryptoTokenV4 token = getCryptoToken();
        if (token != null) {
            token.releaseCryptoInstance(instance, context);

            // Unregister the instance
            CryptoInstances.getInstance(context).remove(instance);
        }
    }
    
    @Override
    public TokenSearchResults searchTokenEntries(int startIndex, int max, final QueryCriteria qc, final boolean includeData, final Map<String, Object> params, final IServices servicesImpl) throws
            CryptoTokenOfflineException,
            QueryException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            OperationUnsupportedException {
        try {
            final ICryptoTokenV4 token = getCryptoToken();
            return token.searchTokenEntries(startIndex, max, qc, includeData, params, servicesImpl);
        } catch (SignServerException ex) {
            log.error(FAILED_TO_GET_CRYPTO_TOKEN_ + ex.getMessage());
            throw new CryptoTokenOfflineException(ex);
        }
    }

}
