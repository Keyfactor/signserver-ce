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
package org.signserver.module.onetime.cryptoworker;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.crypto.SecretKey;
import javax.persistence.EntityManager;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.server.cryptotokens.CryptoInstances;
import org.signserver.server.cryptotokens.DefaultCryptoInstance;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenInitializationFailureException;
import org.signserver.common.DuplicateAliasException;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.KeyTestResult;
import org.signserver.common.NoSuchAliasException;
import org.signserver.common.QueryException;
import org.signserver.common.TokenOutOfSpaceException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.server.IServices;
import org.signserver.server.SignServerContext;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;
import org.signserver.server.signers.CryptoWorker;
import static org.signserver.common.SignServerConstants.DEFAULT_NULL;
import org.signserver.module.onetime.caconnector.CAException;
import org.signserver.module.onetime.caconnector.CAResponse;
import org.signserver.module.onetime.caconnector.ICAConnector;
import org.signserver.server.cryptotokens.BaseCryptoToken;

/**
 * CryptoWorker generating a new key-pair for each request and using a CA
 * connector to get a new certificate for it.
 *
 * @author Markus Kilås
 * @version $Id: OneTimeCryptoWorker.java 9525 2018-09-27 14:48:35Z vinays $
 */
public class OneTimeCryptoWorker extends CryptoWorker {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(OneTimeCryptoWorker.class);

    // Worker properties
    public static final String PROPERTY_KEYALG = "KEYALG";
    public static final String PROPERTY_KEYSPEC = "KEYSPEC";
    public static final String PROPERTY_KEYALIAS_PREFIX = "KEYALIAS_PREFIX";
    public static final String PROPERTY_CACONNECTOR_IMPLEMENTATION = "CACONNECTOR_IMPLEMENTATION";

    // Default values
    private static final String DEFAULT_KEYALIAS_PREFIX = "onetime-";

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private String keyalg;
    private String keyspec;
    private String keyaliasPrefix;
    private ICAConnector ca;

    @Override
    public void init(final int workerId, final WorkerConfig config, 
                     final WorkerContext workerContext, final EntityManager workerEM)  {
        super.init(workerId, config, workerContext, workerEM);

        // Required property KEYALG
        keyalg = config.getProperty(PROPERTY_KEYALG, DEFAULT_NULL);
        if (keyalg == null) {
            configErrors.add("Missing required property: " + PROPERTY_KEYALG);
        }
        // TODO: Could also check that keyalg is valid
        
        // Required property KEYSPEC
        keyspec = config.getProperty(PROPERTY_KEYSPEC, DEFAULT_NULL);
        if (keyspec == null) {
            configErrors.add("Missing required property: " + PROPERTY_KEYSPEC);
        }
        // TODO: Could also check that keyspec is valid
        
        try {
            // Check that the one time crypto woker is not disabled
            // If disabled, no need to connect and check CA connector
            CryptoTokenHelper.checkEnabled(config.getProperties());

            // Required property PROPERTY_CACONNECTOR_IMPLEMENTATION
            final String caConnector = config.getProperty(PROPERTY_CACONNECTOR_IMPLEMENTATION, DEFAULT_NULL);
            if (caConnector == null) {
                configErrors.add("Missing required property: " + PROPERTY_CACONNECTOR_IMPLEMENTATION);
            } else {
                ca = getCAConnector(caConnector, config, (SignServerContext) workerContext);
            }

            // Optional property KEYALIAS_PREFIX
            keyaliasPrefix = config.getProperty(PROPERTY_KEYALIAS_PREFIX, DEFAULT_KEYALIAS_PREFIX);
        } catch (CryptoTokenInitializationFailureException ex) {
            configErrors.add("Worker is disabled");
        }
    }
    
    private ICAConnector getCAConnector(final String className, final WorkerConfig config,
                                        final SignServerContext context) {
        ICAConnector result;
        try {
            final Class<?> implClass = Class.forName(className);
            final Object obj = implClass.newInstance();
            result = (ICAConnector) obj;
            result.init(config, context);
        } catch (ClassNotFoundException e) {
            configErrors.add("Class not found: " + e.getLocalizedMessage());
            result = null;
        } catch (IllegalAccessException e) {
            configErrors.add("Illegal access: " + e.getLocalizedMessage());
            result = null;
        } catch (InstantiationException e) {
            configErrors.add("Instantiation error: " + e.getLocalizedMessage());
            result = null;
        }
        return result;
    }
    

    @Override
    public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
        final ICryptoTokenV4 delegate = super.getCryptoToken(services);

        // first check whether source crypto token is initialized 
        if (delegate == null) {
            throw new SignServerException("Source crypto token is not initialized");
        }

        return new OneTimeCryptoToken(delegate);
    }
    
    private class OneTimeCryptoToken extends BaseCryptoToken {

        private final ICryptoTokenV4 delegate;
        
        public OneTimeCryptoToken(final ICryptoTokenV4 delegate) {
            this.delegate = delegate;
        }
        
        @Override
        public ICryptoInstance acquireCryptoInstance(final String alias, 
                                                     final Map<String, Object> params,
                                                     final RequestContext context) throws
                CryptoTokenOfflineException,
                NoSuchAliasException, 
                InvalidAlgorithmParameterException,
                UnsupportedCryptoTokenParameter,
                IllegalRequestException,
                SignServerException {
            
            if (!configErrors.isEmpty()) {
                throw new CryptoTokenOfflineException("Crypto worker is misconfigured");
            }            
            
            // Alias to use for the new key
            final String newAlias = keyaliasPrefix + alias + "-" + (String) context.get(RequestContext.TRANSACTION_ID);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Alias: " + newAlias);
            }

            try {
                final ICryptoTokenV4 token4 = (ICryptoTokenV4) delegate;
                token4.generateKey(keyalg, keyspec, newAlias, null, params, context.getServices());

                final ICryptoInstance crypto = token4.acquireCryptoInstance(newAlias, params, context);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Generated public key: " + crypto.getPublicKey());
                }
                
                // Log values
                final LogMap logMap = LogMap.getInstance(context);
                
                logMap.put(IWorkerLogger.LOG_KEYALIAS, new Loggable() {
                    @Override
                    public String toString() {
                        return newAlias;
                    }
                });
                logMap.put(IWorkerLogger.LOG_KEY_ALGORITHM, new Loggable() {
                    @Override
                    public String toString() {
                        return keyalg;
                    }
                });
                logMap.put(IWorkerLogger.LOG_KEY_SPECIFICATION, new Loggable() {
                    @Override
                    public String toString() {
                        return keyspec;
                    }
                });                
                
                final CAResponse certResp = ca.requestCertificate(token4, newAlias, crypto.getPrivateKey(), crypto.getPublicKey(), token4.getKeyStore().getProvider().getName(), context);
                
                if (certResp.getError() == null) {
                    final List<X509CertificateHolder> certificateChain = certResp.getCertificateChain();
                    final ArrayList<Certificate> jcaCerts = new ArrayList<>(certificateChain.size());
                    final JcaX509CertificateConverter conv = new JcaX509CertificateConverter();
                    for (X509CertificateHolder c : certificateChain) {
                        jcaCerts.add(conv.getCertificate(c));
                    }

                    final ICryptoInstance result = new WrappedCryptoInstance(crypto, newAlias, context, crypto.getProvider(), crypto.getPrivateKey(), jcaCerts);

                    // Register the new instance
                    CryptoInstances.getInstance(context).add(result);

                    return result;
                } else {
                    // Remove short lived key if there was error in CA response
                    token4.removeKey(newAlias, context.getServices());
                    
                    LOG.error("CA response: " + certResp.getError());
                    throw new SignServerException("CA response: " + certResp.getError());
                }
            } catch (TokenOutOfSpaceException | DuplicateAliasException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | UnsupportedOperationException | KeyStoreException | IllegalStateException | CertificateException ex) {
                LOG.error(ex, ex);
                throw new SignServerException("Key generation error: " + ex.getLocalizedMessage());
            } catch (CAException ex) {
                LOG.error(ex, ex);
                throw new SignServerException("Backend CA error: " + ex.getLocalizedMessage());
            }
        }

        @Override
        public void releaseCryptoInstance(final ICryptoInstance instance,
                                          final RequestContext context) {
            if (instance instanceof WrappedCryptoInstance) {
                final ICryptoTokenV4 token3 = (ICryptoTokenV4) delegate;
                try {
                    token3.removeKey(((WrappedCryptoInstance) instance).getAlias(), context.getServices());
                    
                    token3.releaseCryptoInstance(((WrappedCryptoInstance) instance).getSourceInstance(), context);
                    
                    // Unregister the instance
                    CryptoInstances.getInstance(context).remove(instance);
                } catch (UnsupportedOperationException | CryptoTokenOfflineException | KeyStoreException | SignServerException ex) {
                    throw new RuntimeException("Unable to remove key", ex);
                }
            }
        }
        
        @Override
        public void init(final int workerId, final Properties props, 
                         final IServices services) throws CryptoTokenInitializationFailureException {
            // Check that the crypto token is not disabled
            CryptoTokenHelper.checkEnabled(props);
            delegate.init(workerId, props, services);
        }

        @Override
        public void activate(final String authenticationcode,
                             final IServices services) 
                throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException {
            delegate.activate(authenticationcode, services);
        }

        @Override
        public boolean deactivate(final IServices services) throws CryptoTokenOfflineException {
            return delegate.deactivate(services);
        }

        @Override
        public KeyStore getKeyStore() throws UnsupportedOperationException, CryptoTokenOfflineException, KeyStoreException {
            return delegate.getKeyStore();
        }

        @Override
        public int getCryptoTokenStatus(final IServices services) {
            int result = WorkerStatus.STATUS_OFFLINE;
            if (delegate != null) {
                result = delegate.getCryptoTokenStatus(services);
                if (result == WorkerStatus.STATUS_ACTIVE && ca != null) {
                    if (ca.getFatalErrors(delegate, services).isEmpty()) {
                        result = WorkerStatus.STATUS_ACTIVE;
                    } else { // Signer should show error when there are errors in ca connector under one time crypto worker
                        result = WorkerStatus.STATUS_OFFLINE;
                    }
                }
            }
            return result;
        }

        @Override
        public void importCertificateChain(final List<Certificate> certChain,
                                           final String alias,
                                           final char[] athenticationCode,
                                           final Map<String, Object> params,
                                           final IServices services)
                throws TokenOutOfSpaceException, CryptoTokenOfflineException,
                       NoSuchAliasException, InvalidAlgorithmParameterException,
                       UnsupportedCryptoTokenParameter {
            delegate.importCertificateChain(certChain, alias, athenticationCode, params, services);
        }

        @Override
        public TokenSearchResults searchTokenEntries(final int startIndex,
                                                     final int max,
                                                     final QueryCriteria qc,
                                                     final boolean includeData,
                                                     final Map<String, Object> params,
                                                     final IServices services)
                throws CryptoTokenOfflineException, QueryException,
                       InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
            return delegate.searchTokenEntries(startIndex, max, qc, includeData, params, services);
        }

        @Override
        public void generateKey(final String keyAlgorithm,
                                final String keySpec,
                                final String alias, final char[] authCode,
                                final Map<String, Object> params,
                                final IServices services)
                throws TokenOutOfSpaceException, CryptoTokenOfflineException,
                       DuplicateAliasException, NoSuchAlgorithmException,
                       InvalidAlgorithmParameterException, UnsupportedCryptoTokenParameter {
            delegate.generateKey(keyAlgorithm, keySpec, alias, authCode, params, services);
        }

        @Override
        public ICertReqData genCertificateRequest(final ISignerCertReqInfo info,
                                                  final boolean explicitEccParameters,
                                                  final String keyAlias,
                                                  final IServices services)
                throws CryptoTokenOfflineException, NoSuchAliasException {
            return delegate.genCertificateRequest(info, explicitEccParameters, keyAlias, services);
        }

        @Override
        public Collection<KeyTestResult> testKey(final String alias,
                                                 final char[] authCode,
                                                 final IServices Services)
                throws CryptoTokenOfflineException, KeyStoreException {
            return delegate.testKey(alias, authCode, Services);
        }

        @Override
        public boolean removeKey(final String alias, final IServices services)
                throws CryptoTokenOfflineException, KeyStoreException, SignServerException {
            return delegate.removeKey(alias, services);
        }
        
        @Override
        public boolean isNoCertificatesRequired() {
            // Signer certificate will be created & uploaded at the time of actual signing operation through CA connector so no certificates required as of now
            return true;
        }
    }
    
    @Override
    protected List<String> getFatalErrors(final IServices services) {
        // Add our errors to the list of errors
        final LinkedList<String> errors = new LinkedList<>(
                super.getFatalErrors(services));
        errors.addAll(configErrors);
        if (ca != null) {
            try {
                ICryptoTokenV4 backingCryptoToken = (ICryptoTokenV4) super.getCryptoToken(services);
                errors.addAll(ca.getFatalErrors(backingCryptoToken, services));
            } catch (SignServerException ex) {
                errors.add("Token error: " + ex.getLocalizedMessage());
            }
        }
        return errors;
    }
    
    private static class WrappedCryptoInstance extends DefaultCryptoInstance {
        
        private final ICryptoInstance sourceInstance;
        
        public WrappedCryptoInstance(final ICryptoInstance sourceInstance,
                                     final String alias,
                                     final RequestContext context,
                                     final Provider provider,
                                     final PrivateKey privateKey,
                                     final List<Certificate> certificateChain) {
            super(alias, context, provider, privateKey, certificateChain);
            this.sourceInstance = sourceInstance;
        }

        public ICryptoInstance getSourceInstance() {
            return sourceInstance;
        }
        
    }

    @Override
    protected ICryptoInstance acquireDefaultCryptoInstance(final String alias,
                                                           final RequestContext context)
            throws CryptoTokenOfflineException, InvalidAlgorithmParameterException,
                   UnsupportedCryptoTokenParameter, IllegalRequestException, SignServerException {
        // This crypto token does not have one certificate of its own,
        // lets just return the one from its upstream crypto token
        return new ICryptoInstance() {
            @Override
            public Certificate getCertificate() {
                return null;
            }

            @Override
            public List<Certificate> getCertificateChain() {
                return null;
            }

            @Override
            public PrivateKey getPrivateKey() {
                return null;
            }

            @Override
            public PublicKey getPublicKey() {
                return null;
            }

            @Override
            public SecretKey getSecretKey() {
                return null;
            }

            @Override
            public Provider getProvider() {
                return null;
            }
        };
    }
}
