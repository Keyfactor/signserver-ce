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
package org.signserver.ejb;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.naming.NamingException;
import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionLocal;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.CertTools;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.admin.common.config.RekeyUtil;
import org.signserver.common.*;
import org.signserver.common.KeyTestResult;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.ejb.worker.impl.WorkerManagerSingletonBean;
import org.signserver.server.*;
import org.signserver.server.archive.olddbarchiver.entities.ArchiveDataBean;
import org.signserver.server.archive.olddbarchiver.entities.ArchiveDataService;
import org.signserver.server.cesecore.AlwaysAllowLocalAuthenticationToken;
import org.signserver.server.config.entities.FileBasedWorkerConfigDataService;
import org.signserver.server.config.entities.IWorkerConfigDataService;
import org.signserver.server.config.entities.WorkerConfigDataService;
import org.signserver.common.DuplicateAliasException;
import org.signserver.common.NoSuchAliasException;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.DispatcherProcessSessionLocal;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.ejb.worker.impl.WorkerWithComponents;
import org.signserver.server.entities.FileBasedKeyUsageCounterDataService;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounter;
import org.signserver.server.entities.KeyUsageCounterDataService;
import org.signserver.server.log.*;
import org.signserver.server.nodb.FileBasedDatabaseManager;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionRemote;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;
import org.signserver.ejb.interfaces.ServiceTimerSessionLocal;
import org.signserver.server.archive.Archiver;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import org.signserver.statusrepo.StatusRepositorySessionLocal;

/**
 * The main worker session bean.
 * 
 * @version $Id$
 */
@Stateless
public class WorkerSessionBean implements WorkerSessionLocal, WorkerSessionRemote {
    
    /** Log4j instance for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerSessionBean.class);
   
    /** The local home interface of Worker Config entity bean. */
    private IWorkerConfigDataService workerConfigService;
    
    /** The local home interface of archive entity bean. */
    private ArchiveDataService archiveDataService;
    
    private IKeyUsageCounterDataService keyUsageCounterDataService;

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @EJB
    private ServiceTimerSessionLocal serviceTimerSession;
    
    @EJB
    private WorkerManagerSingletonBean workerManagerSession;
    
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    @EJB
    private SecurityEventsAuditorSessionLocal auditorSession;
    
    @Resource
    private SessionContext ctx;
    
    EntityManager em;

    private final AllServicesImpl servicesImpl = new AllServicesImpl();

    @PostConstruct
    public void create() {
        if (em == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No EntityManager injected. Running without database.");
            }
            workerConfigService = new FileBasedWorkerConfigDataService(FileBasedDatabaseManager.getInstance());
            keyUsageCounterDataService = new FileBasedKeyUsageCounterDataService(FileBasedDatabaseManager.getInstance());
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("EntityManager injected. Running with database.");
            }
            workerConfigService = new WorkerConfigDataService(em);
            archiveDataService = new ArchiveDataService(em);
            keyUsageCounterDataService = new KeyUsageCounterDataService(em);
        }

        // XXX The lookups will fail on GlassFish V2
        // When we no longer support GFv2 we can refactor this code
        InternalProcessSessionLocal internalSession = null;
        DispatcherProcessSessionLocal dispatcherSession = null;
        StatusRepositorySessionLocal statusSession = null;
        try {
            internalSession = ServiceLocator.getInstance().lookupLocal(InternalProcessSessionLocal.class);
            dispatcherSession = ServiceLocator.getInstance().lookupLocal(DispatcherProcessSessionLocal.class);
            statusSession = ServiceLocator.getInstance().lookupLocal(StatusRepositorySessionLocal.class);
        } catch (NamingException ex) {
            LOG.error("Lookup services failed. This is expected on GlassFish V2: " + ex.getExplanation());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Lookup services failed", ex);
            }
        }
        try {
            // Add all services
            servicesImpl.putAll(em,
                    ctx.getBusinessObject(WorkerSessionLocal.class),
                    ServiceLocator.getInstance().lookupLocal(ProcessSessionLocal.class),
                    globalConfigurationSession,
                    logSession,
                    internalSession, dispatcherSession, statusSession,
                    keyUsageCounterDataService);
        } catch (NamingException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Lookup services failed", ex);
            }
        }
    }
    
    /**
     * Gets the last date the specified worker can do signings.
     * @param wi Id of worker to check.
     * @return The last date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
    @Override
    public Date getSigningValidityNotAfter(final WorkerIdentifier wi)
            throws CryptoTokenOfflineException {
        Date date = null;
        final Certificate signerCert = getSignerCertificate(wi);
        if (signerCert instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate) signerCert;
            try {
                IWorker worker = workerManagerSession.getWorker(wi);
                date = ValidityTimeUtils.getSigningValidity(true, wi,
                    worker.getConfig(), cert);
            } catch (NoSuchWorkerException ex) {
                throw new CryptoTokenOfflineException(ex.getLocalizedMessage());
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Worker does not have a signing certificate. Worker: "
                        + wi);
            }
        }
        return date;
    }

    /**
     * Gets the first date the specified worker can do signings.
     * @param workerId Id of worker to check.
     * @return The first date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
    @Override
    public Date getSigningValidityNotBefore(final WorkerIdentifier workerId)
            throws CryptoTokenOfflineException {
        Date date = null;
        final Certificate signerCert = getSignerCertificate(workerId);
        if (signerCert instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate) signerCert;
            try {
                IWorker worker = workerManagerSession.getWorker(workerId);
                date = ValidityTimeUtils.getSigningValidity(false, workerId,
                    worker.getConfig(), cert);
            } catch (NoSuchWorkerException ex) {
                throw new CryptoTokenOfflineException(ex.getLocalizedMessage());
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Worker does not have a signing certificate. Worker: "
                        + workerId);
            }
        }
        return date;
    }

    /**
     * Returns the value of the KeyUsageCounter for the given workerId. If no
     * certificate is configured for the worker or the current key does not yet
     * have a counter in the database -1 is returned.
     * @param workerId
     * @return Value of the key usage counter or -1
     * @throws CryptoTokenOfflineException
     */
    @Override
    public long getKeyUsageCounterValue(final WorkerIdentifier workerId) 
            throws CryptoTokenOfflineException {
        long result;
        try {
            final Certificate cert = getSignerCertificate(workerId);
            if (cert == null) {
                result = -1;
            } else {
                final String pk
                        = KeyUsageCounterHash.create(cert.getPublicKey());
                final KeyUsageCounter signings
                        = keyUsageCounterDataService.getCounter(pk);
                if (signings == null) {
                    result = -1;
                } else {
                    result = signings.getCounter();
                }
            }
            return result;
        } catch (IllegalArgumentException ex) {
            LOG.error(ex, ex);
            throw new CryptoTokenOfflineException(ex);
        }
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#getStatus(int)
     */
    @Override
    public WorkerStatus getStatus(WorkerIdentifier workerId) throws InvalidWorkerIdException {
        final List<String> errorsAtEjbLevel = new LinkedList<>();
        WorkerWithComponents worker = null;
        try {
            worker = workerManagerSession.getWorkerWithComponents(workerId);
            
            final List<Archiver> archivers = worker.getArchivers();
            if (archivers != null) {
                for (final Archiver archiver : worker.getArchivers()) {
                    errorsAtEjbLevel.addAll(archiver.getFatalErrors());
                }
            }

            final IWorkerLogger logger = worker.getWorkerLogger();
            if (logger != null) {
                errorsAtEjbLevel.addAll(logger.getFatalErrors(servicesImpl));
            }
            
            errorsAtEjbLevel.addAll(worker.getCreateErrors());
        
            return new StaticWorkerStatus(worker.getWorker().getStatus(errorsAtEjbLevel, servicesImpl));
        } catch (NoSuchWorkerException ex) {
            throw new InvalidWorkerIdException(ex.getMessage());
        }
    }

    @Override
    public boolean isTokenActive(WorkerIdentifier workerId) throws InvalidWorkerIdException {
        boolean result;
        try {
            IWorker worker = workerManagerSession.getWorker(workerId);
            if (worker instanceof IProcessable) {
                IProcessable processable = (IProcessable) worker;
                result = processable.getCryptoTokenStatus(servicesImpl) == WorkerStatus.STATUS_ACTIVE;
            } else {
                result = false; // Does not have a token
            }
        } catch (NoSuchWorkerException ex) {
            throw new InvalidWorkerIdException(ex.getMessage());
        }
        return result;
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#getWorkerId(java.lang.String)
     */
    // XXX: Somewhat expensive call, good to avoid as much as possible. Seems to be only config operations really needing the ID all other could use WorkerIdentifier
    @Override
    public int getWorkerId(String signerName) throws InvalidWorkerIdException {
        try {
            return workerManagerSession.getWorkerWithComponents(new WorkerIdentifier(signerName)).getId();
        } catch (NoSuchWorkerException ex) {
            throw new InvalidWorkerIdException(ex.getMessage());
        }
    }
   
    @Override
    public void reloadConfiguration(int workerId) {
        reloadConfiguration(new AdminInfo("CLI user", null, null), workerId);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSessionLocal#reloadConfiguration(adminInfo, int)
     */
    @Override
    public void reloadConfiguration(final AdminInfo adminInfo, int workerId) {
        if (workerId == 0) {
            globalConfigurationSession.reload(adminInfo);
        } else {
            workerManagerSession.reloadWorker(new WorkerIdentifier(workerId));
            auditLog(adminInfo, SignServerEventTypes.RELOAD_WORKER_CONFIG, EventStatus.SUCCESS, SignServerModuleTypes.WORKER_CONFIG,
                    new WorkerIdentifier(workerId), Collections.<String, Object>emptyMap());
                
            // Try to initialize the key usage counter
            try {
                initKeyUsageCounter(workerManagerSession.getWorker(new WorkerIdentifier(workerId)), servicesImpl);
            } catch (NoSuchWorkerException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Worker no longer exists so not initializing key usage counter: " + ex.getMessage());
                }
            }
        }

        if (workerId == 0 || getWorkers(
                WorkerType.TIMED_SERVICE).contains(
                workerId)) {
            serviceTimerSession.unload(workerId);
            serviceTimerSession.load(workerId);
        }
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#activateSigner(int, java.lang.String)
     */
    @Override
    public void activateSigner(WorkerIdentifier signerId, String authenticationCode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException, InvalidWorkerIdException {
        try {
            IWorker worker = workerManagerSession.getWorker(signerId);

            if (!(worker instanceof IProcessable)) {
                throw new InvalidWorkerIdException(
                        "Worker exists but isn't a signer.");
            }
            IProcessable signer = (IProcessable) worker;
            
            signer.activateSigner(authenticationCode, servicesImpl);
            
            // Try to initialize the key usage counter
            initKeyUsageCounter(worker, servicesImpl);
        } catch (NoSuchWorkerException ex) {
            throw new InvalidWorkerIdException(ex.getMessage());
        }
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#deactivateSigner(int)
     */
    @Override
    public boolean deactivateSigner(WorkerIdentifier signerId)
            throws CryptoTokenOfflineException, InvalidWorkerIdException {
        try {
            IWorker worker = workerManagerSession.getWorker(signerId);

            if (!(worker instanceof IProcessable)) {
                throw new InvalidWorkerIdException(
                        "Worker exists but isn't a signer.");
            }
            IProcessable signer = (IProcessable) worker;
            
            return signer.deactivateSigner(servicesImpl);
        } catch (NoSuchWorkerException ex) {
            throw new InvalidWorkerIdException(ex.getMessage());
        }
    }

    @Override
    public String generateSignerKey(final WorkerIdentifier signerId, String keyAlgorithm,
            String keySpec, String alias, final char[] authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
                IllegalArgumentException {
    	return generateSignerKey(new AdminInfo("CLI user", null, null), signerId, keyAlgorithm,
    			keySpec, alias, authCode);
    }

    @Override
    public String generateSignerKey(final AdminInfo adminInfo, final WorkerIdentifier signerId, String keyAlgorithm,
            String keySpec, String alias, final char[] authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
                IllegalArgumentException {

        // Check that key generation is not disabled
        if (isKeyGenerationDisabled()) {
            throw new CryptoTokenOfflineException("Key generation has been disabled");
        }

        try {
            IWorker worker = workerManagerSession.getWorker(signerId);

            if (!(worker instanceof IProcessable)) {
                throw new InvalidWorkerIdException(
                        "Worker exists but isn't a signer.");
            }
            final IProcessable signer = (IProcessable) worker;

            final WorkerConfig config = worker.getConfig();

            if (keyAlgorithm == null) {
                keyAlgorithm = config.getProperty("KEYALG");
            }
            if (keySpec == null) {
                keySpec = config.getProperty("KEYSPEC");
            }
            if (alias == null) {
                final String currentAlias = config.getProperty("DEFAULTKEY");
                if (currentAlias == null) {
                    throw new IllegalArgumentException("No key alias specified");
                } else {
                    alias = RekeyUtil.nextAliasInSequence(currentAlias);
                }
            }
            
            // As we don't yet have a way to directly pass key generation parameters
            // we are now instead taking those from worker properties.
            // In the future the properties would just be default values used by
            // the interfaces when asking the user for the values and the actual
            // values to use could come as parameters to this method.
            final HashMap<String, Object> params = new HashMap<>(3);
            final String dn = (String) config.getProperty(CryptoTokenHelper.PROPERTY_SELFSIGNED_DN);
            if (dn != null) {
                params.put(CryptoTokenHelper.PROPERTY_SELFSIGNED_DN, dn);
            }

            final String validityValue = (String) config.getProperty(CryptoTokenHelper.PROPERTY_SELFSIGNED_VALIDITY);
            if (validityValue != null) {
                try {
                    final long validity = Long.parseLong(validityValue);
                    params.put(CryptoTokenHelper.PROPERTY_SELFSIGNED_VALIDITY, validity);
                } catch (NumberFormatException ex) {
                    throw new IllegalArgumentException("Incorrect nummeric value for property " + CryptoTokenHelper.PROPERTY_SELFSIGNED_VALIDITY + ": " + ex.getLocalizedMessage());
                }
            }

            final String signatureAlgorithm = (String) config.getProperty(CryptoTokenHelper.PROPERTY_SELFSIGNED_SIGNATUREALGORITHM);
            if (signatureAlgorithm != null) {
                params.put(CryptoTokenHelper.PROPERTY_SELFSIGNED_SIGNATUREALGORITHM, signatureAlgorithm);
            }
            
            final String generateCertValue = (String) config.getProperty(CryptoTokenHelper.PROPERTY_GENERATE_CERTIFICATE_OBJECT);
            if (generateCertValue != null) {
                final boolean generate;
                if (generateCertValue.trim().equalsIgnoreCase(Boolean.TRUE.toString())) {
                    generate = true;
                } else if (generateCertValue.trim().equalsIgnoreCase(Boolean.FALSE.toString())) {
                    generate = false;
                } else {
                    throw new IllegalArgumentException("Incorrect boolean value for property " + CryptoTokenHelper.PROPERTY_GENERATE_CERTIFICATE_OBJECT);
                }
                params.put(CryptoTokenHelper.PROPERTY_GENERATE_CERTIFICATE_OBJECT, generate);
            }

            signer.generateKey(keyAlgorithm, keySpec, alias, authCode, params,
                    servicesImpl);

            final HashMap<String, Object> auditMap = new HashMap<>();
            auditMap.put(AdditionalDetailsTypes.KEYALG.name(), keyAlgorithm);
            auditMap.put(AdditionalDetailsTypes.KEYSPEC.name(), keySpec);
            auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), alias);
            auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(signerId, config));
            auditLog(adminInfo, SignServerEventTypes.KEYGEN, EventStatus.SUCCESS, SignServerModuleTypes.KEY_MANAGEMENT, signerId, auditMap);
            return alias;
        } catch (DuplicateAliasException ex) {
            throw new IllegalArgumentException("The specified alias already exists");
        } catch (NoSuchAlgorithmException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No such algorithm", ex);
            }
            throw new IllegalArgumentException("No such algorithm");
        } catch (InvalidAlgorithmParameterException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Invalid or inappropriate algorithm parameters", ex);
            }
            throw new IllegalArgumentException("Invalid or inappropriate algorithm parameters");
        } catch (UnsupportedCryptoTokenParameter ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unsupported crypto token parameter", ex);
            }
            throw new IllegalArgumentException("Unsupported crypto token parameter");
        } catch (NoSuchWorkerException ex) {
            throw new InvalidWorkerIdException(ex.getMessage());
        }
    }
    
    /**
     * Get the name of the configured crypto token or if none, the name or
     * ID of the current worker.
     * @param workerId of the worker
     * @param config for the worker
     * @return name of crypto token or the worker name or id
     */
    private static String getCryptoToken(final WorkerIdentifier workerId, final WorkerConfig config) {
        String result = config.getProperty("CRYPTOTOKEN");
        if (result == null) {
            result = config.getProperty("NAME");
            if (result == null) {
                result = String.valueOf(workerId);
            }
        }
        return result;
    }

    @Override
    public Collection<KeyTestResult> testKey(final WorkerIdentifier signerId, String alias,
            char[] authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            KeyStoreException {
    	return testKey(new AdminInfo("CLI user", null, null), signerId, alias, authCode);
    }
    
    @Override
    public Collection<KeyTestResult> testKey(final AdminInfo adminInfo, final WorkerIdentifier signerId, String alias,
            char[] authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            KeyStoreException {

        try {
            IWorker worker = workerManagerSession.getWorker(signerId);
            
            if (!(worker instanceof IProcessable)) {
                throw new InvalidWorkerIdException(
                        "Worker exists but isn't a signer.");
            }
            final IProcessable signer = (IProcessable) worker;
            
            final WorkerConfig config = worker.getConfig();
            
            // If alias is not specified used TESTKEY or alternatively DEFAULTKEY
            if (alias == null) {
                alias = config.getProperty("TESTKEY");
                if (alias == null) {
                    alias = config.getProperty("DEFAULTKEY");
                }
            }
            
            final Collection<KeyTestResult> result = signer.testKey(alias, authCode, servicesImpl);
            
            final HashMap<String, Object> auditMap = new HashMap<>();
            auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), alias);
            auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(signerId, config));
            auditMap.put(AdditionalDetailsTypes.TESTRESULTS.name(), createResultsReport(result));
            auditLog(adminInfo, SignServerEventTypes.KEYTEST, EventStatus.SUCCESS, SignServerModuleTypes.KEY_MANAGEMENT, signerId, auditMap);
            
            return result;
        } catch (NoSuchWorkerException ex) {
            throw new InvalidWorkerIdException(ex.getMessage());
        }
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.WorkerSession#getCurrentSignerConfig(int)
     */
    @Override
    public WorkerConfig getCurrentWorkerConfig(int signerId) {
        final WorkerConfig config = new WorkerConfig();
        final Properties workerProps =
                getWorkerConfig(signerId).getProperties();
        
        config.setProperties(workerProps);
        
        return config;
    }

    @Override
    public Properties exportWorkerConfig(final int signerId) {
        final WorkerConfig config = getCurrentWorkerConfig(signerId);
        final Properties allProps = config.getProperties();
        final Properties exportedProps = new Properties();
        
        for (final String key : allProps.stringPropertyNames()) {
            if (config.shouldMaskProperty(key)) {
                exportedProps.put(key, WorkerConfig.WORKER_PROPERTY_MASK_PLACEHOLDER);
            } else {
                exportedProps.put(key, allProps.getProperty(key));
            }
        }
        
        return exportedProps;
    }
    
    @Override
    public byte[] getKeystoreData(AdminInfo adminInfo, int signerId) {
        WorkerConfig config = getWorkerConfig(signerId);
        
        return config.getKeystoreData();
    }

    @Override
    public void setKeystoreData(AdminInfo adminInfo, int signerId, byte[] keystoreData) {
        WorkerConfig config = getWorkerConfig(signerId);
        config.setKeystoreData(keystoreData);
        setWorkerConfig(adminInfo, signerId, config, "set:keystore_data", null);
    }

    @Override
    public void updateWorkerProperties(int workerId,
                                       Map<String, String> propertiesAndValues,
                                       List<String> propertiesToRemove) {
        updateWorkerProperties(new AdminInfo("CLI user", null, null), workerId,
                               propertiesAndValues, propertiesToRemove);
    }
    
    @Override
    public void updateWorkerProperties(AdminInfo adminInfo, int workerId,
                                       Map<String, String> propertiesAndValues,
                                       List<String> propertiesToRemove) {

        WorkerConfig config = getWorkerConfig(workerId);

        
        //First we add the added and changed properties to the config
        for (Map.Entry mapElement : propertiesAndValues.entrySet()) {
            config.setProperty((String)mapElement.getKey(), (String)mapElement.getValue());
        }
       
        //We extend the hashmap with all values that shall be removed
        //for logging ourposes, the log will go through all items in the HM-hashmap
        for (String toDelete: propertiesToRemove) {
            propertiesAndValues.put(toDelete, "REMOVED");
        }
        
        //Then we remove all properties that are on the remove-list
        for (String propertyToRemove: propertiesToRemove) {
            config.removeProperty(propertyToRemove.toUpperCase());
        }
        if (config.getProperties().size() <= config.getVirtualPropertiesNumber()) {
            workerConfigService.removeWorkerConfig(workerId);
            LOG.debug("WorkerConfig is empty and therefore removed.");
            auditLog(adminInfo, SignServerEventTypes.SET_WORKER_CONFIG, SignServerModuleTypes.WORKER_CONFIG, new WorkerIdentifier(workerId));
        } else {
            setWorkerConfig(adminInfo, workerId, config, null, null);
        }
        
        auditLogWorkerPropertyChange(adminInfo, new WorkerIdentifier(workerId),
                                     config, propertiesAndValues.keySet().toString(),
                                     propertiesAndValues.values().toString());
    }
    
    @Override
    public void setWorkerProperty(int workerId, String key, String value) {
    	setWorkerProperty(new AdminInfo("CLI user", null, null), workerId, key, value);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#setWorkerProperty(int, java.lang.String, java.lang.String)
     */
    @Override
    public void setWorkerProperty(final AdminInfo adminInfo, int workerId, String key, String value) {
        // Special case for auto-detecting worker type
        if (WorkerConfig.TYPE.equalsIgnoreCase(key) && (value == null || value.trim().isEmpty())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Auto-detecting worker type");
            }
            try {
                IWorker obj = workerManagerSession.getWorker(new WorkerIdentifier(workerId));
                value = obj.getWorkerType().name();
            } catch (NoSuchWorkerException ex) {
                LOG.error("Unable to auto-detect worker type as the worker can not be found: " + ex.getWorkerIdOrName());
            }
        }
        WorkerConfig config = getWorkerConfig(workerId);
        config.setProperty(key.toUpperCase(Locale.ENGLISH), value);
        setWorkerConfig(adminInfo, workerId, config, null, null);
        auditLogWorkerPropertyChange(adminInfo, new WorkerIdentifier(workerId), config, key, value);
    }
    
    private void auditLogCertInstalled(final AdminInfo adminInfo, final WorkerIdentifier workerId, final String value, final String scope, final String node) {
        final HashMap<String, Object> auditMap = new HashMap<>();
        auditMap.put(AdditionalDetailsTypes.CERTIFICATE.name(), value);
        auditMap.put(AdditionalDetailsTypes.SCOPE.name(), scope);
        if ("NODE".equalsIgnoreCase(scope)) {
            auditMap.put(AdditionalDetailsTypes.NODE.name(), node);
        }
        auditLog(adminInfo, SignServerEventTypes.CERTINSTALLED, EventStatus.SUCCESS, SignServerModuleTypes.WORKER_CONFIG, workerId, auditMap);
    }
    
    private void auditLogCertChainInstalled(final AdminInfo adminInfo, final WorkerIdentifier workerId, final String value, final String scope, final String node) {
        final HashMap<String, Object> auditMap = new HashMap<>();
        auditMap.put(AdditionalDetailsTypes.CERTIFICATECHAIN.name(), value);
        auditMap.put(AdditionalDetailsTypes.SCOPE.name(), scope);
        if ("NODE".equalsIgnoreCase(scope)) {
            auditMap.put(AdditionalDetailsTypes.NODE.name(), node);
        }
        auditLog(adminInfo, SignServerEventTypes.CERTCHAININSTALLED, EventStatus.SUCCESS, SignServerModuleTypes.WORKER_CONFIG, workerId, auditMap);
    }
    
    private void auditLogCertChainInstalledToToken(final AdminInfo adminInfo, EventStatus outcome, final WorkerIdentifier workerId, final WorkerConfig config, final String alias, final String value, final String error) {
        final HashMap<String, Object> auditMap = new HashMap<>();
        auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), alias);
        auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(workerId, config));
        auditMap.put(AdditionalDetailsTypes.CERTIFICATECHAIN.name(), value);
        if (error != null) {
            auditMap.put(AdditionalDetailsTypes.ERROR.name(), error);
        }
        auditLog(adminInfo, SignServerEventTypes.CERTCHAININSTALLED, outcome, SignServerModuleTypes.KEY_MANAGEMENT, workerId, auditMap);
    }
    
    @Override
    public boolean removeWorkerProperty(int workerId, String key) {
    	return removeWorkerProperty(new AdminInfo("CLI user", null, null), workerId, key);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#removeWorkerProperty(int, java.lang.String)
     */
    @Override
    public boolean removeWorkerProperty(final AdminInfo adminInfo, int workerId, String key) {
        final boolean result;
        WorkerConfig config = getWorkerConfig(workerId);

        result = config.removeProperty(key.toUpperCase(Locale.ENGLISH));
        if (config.getProperties().size() <= config.getVirtualPropertiesNumber()) {
            workerConfigService.removeWorkerConfig(workerId);
            LOG.debug("WorkerConfig is empty and therefore removed.");
            auditLog(adminInfo, SignServerEventTypes.SET_WORKER_CONFIG, SignServerModuleTypes.WORKER_CONFIG, new WorkerIdentifier(workerId));
        } else {
            setWorkerConfig(adminInfo, workerId, config, null, null);
        }
        auditLogWorkerPropertyChange(adminInfo, new WorkerIdentifier(workerId), config, key, "");
        return result;
    }
    
    private void auditLogWorkerPropertyChange(final AdminInfo adminInfo, final WorkerIdentifier workerId, final WorkerConfig config, final String key, final String value) {
        if ("DEFAULTKEY".equalsIgnoreCase(key)) {
            final HashMap<String, Object> auditMap = new HashMap<>();
            auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), value);
            auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(workerId, config));
            auditMap.put(AdditionalDetailsTypes.SCOPE.name(), "GLOBAL");
            auditLog(adminInfo, SignServerEventTypes.KEYSELECTED, EventStatus.SUCCESS, SignServerModuleTypes.WORKER_CONFIG, workerId, auditMap);
        } else if (key != null && key.lastIndexOf(".") != -1 && key.substring(key.lastIndexOf(".")).equalsIgnoreCase(".DEFAULTKEY")) {
            final HashMap<String, Object> auditMap = new HashMap<>();
            auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), value);
            auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(workerId, config));
            auditMap.put(AdditionalDetailsTypes.SCOPE.name(), "NODE");
            auditMap.put(AdditionalDetailsTypes.NODE.name(), key.substring(0, key.lastIndexOf(".")));
            auditLog(adminInfo, SignServerEventTypes.KEYSELECTED, EventStatus.SUCCESS, SignServerModuleTypes.WORKER_CONFIG, workerId, auditMap);
        } else if (PropertiesConstants.SIGNERCERT.equalsIgnoreCase(key)) {
            auditLogCertInstalled(adminInfo, workerId, value, "GLOBAL", null);
        } else if (key != null && key.lastIndexOf(".") != -1 && key.substring(key.lastIndexOf(".")).equalsIgnoreCase("." + PropertiesConstants.SIGNERCERT)) {
            auditLogCertInstalled(adminInfo, workerId, value, "NODE", key.substring(0, key.lastIndexOf(".")));
        } else if (PropertiesConstants.SIGNERCERTCHAIN.equalsIgnoreCase(key)) {
            auditLogCertChainInstalled(adminInfo, workerId, value, "GLOBAL", null);
        } else if (key != null && key.lastIndexOf(".") != -1 && key.substring(key.lastIndexOf(".")).equalsIgnoreCase("." + PropertiesConstants.SIGNERCERTCHAIN)) {
            auditLogCertChainInstalled(adminInfo, workerId, value, "NODE", key.substring(0, key.lastIndexOf(".")));
        }
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#getAuthorizedClients(int)
     */
    @Override
    public Collection<AuthorizedClient> getAuthorizedClients(int signerId) {
        return getWorkerConfig(signerId).getAuthorizedClients();
    }
    
    @Override
    public Collection<CertificateMatchingRule> getAuthorizedClientsGen2(int signerId) {
        return getWorkerConfig(signerId).getAuthorizedClientsGen2();
    }

    @Override
    public void addAuthorizedClient(int signerId, AuthorizedClient authClient) {
    	addAuthorizedClient(new AdminInfo("CLI user", null, null), signerId, authClient);
    }
    
    @Override
    public void addAuthorizedClientGen2(int signerId, CertificateMatchingRule authClient) {
    	addAuthorizedClientGen2(new AdminInfo("CLI user", null, null), signerId, authClient);
    }
    
    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#addAuthorizedClient(int, org.signserver.common.AuthorizedClient)
     */
    @Override
    public void addAuthorizedClient(final AdminInfo adminInfo, int signerId, AuthorizedClient authClient) {
        WorkerConfig config = getWorkerConfig(signerId);
        config.addAuthorizedClient(authClient);
        setWorkerConfig(adminInfo, signerId, config, "added:authorized_client",
        		"SN: " + authClient.getCertSN() + ", issuer DN: " + authClient.getIssuerDN());
    }
    
    @Override
    public void addAuthorizedClientGen2(final AdminInfo adminInfo, int signerId, CertificateMatchingRule authClient) {
        WorkerConfig config = getWorkerConfig(signerId);
        config.addAuthorizedClientGen2(authClient);
        setWorkerConfig(adminInfo, signerId, config, "added:authorized_client_gen2", authClient.toString());
    }

    @Override
    public boolean removeAuthorizedClient(int signerId, AuthorizedClient authClient) {
    	return removeAuthorizedClient(new AdminInfo("CLI user", null, null), signerId, authClient);
    }
    
    @Override
    public boolean removeAuthorizedClientGen2(int signerId, CertificateMatchingRule authClient) {
    	return removeAuthorizedClientGen2(new AdminInfo("CLI user", null, null), signerId, authClient);
    }
    
    @Override
    public boolean removeAuthorizedClient(final AdminInfo adminInfo, int signerId,
            AuthorizedClient authClient) {
        boolean result;
        WorkerConfig config = getWorkerConfig(signerId);


        result = config.removeAuthorizedClient(authClient);
        setWorkerConfig(adminInfo, signerId, config, "removed:authorized_client",
        		"SN: " + authClient.getCertSN() + ", issuer DN: " + authClient.getIssuerDN());
        return result;
    }
    
    @Override
    public boolean removeAuthorizedClientGen2(final AdminInfo adminInfo, int signerId,
            CertificateMatchingRule authClient) {
        boolean result;
        WorkerConfig config = getWorkerConfig(signerId);

        result = config.removeAuthorizedClientGen2(authClient);
        setWorkerConfig(adminInfo, signerId, config, "removed:authorized_client_gen2", authClient.toString());
        return result;
    }

    @Override
    public ICertReqData getCertificateRequest(final WorkerIdentifier signerId,
            final ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
    	return getCertificateRequest(new AdminInfo("CLI user", null, null), signerId, certReqInfo,
    			explicitEccParameters);
    }
    
    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#getCertificateRequest(int, org.signserver.common.ISignerCertReqInfo)
     */
    @Override
    public ICertReqData getCertificateRequest(final AdminInfo adminInfo, final WorkerIdentifier signerId,
            final ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
        return getCertificateRequest(adminInfo, signerId, certReqInfo, 
                explicitEccParameters, true);
    }

    @Override
    public ICertReqData getCertificateRequest(WorkerIdentifier signerId,
            ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters,
            final boolean defaultKey) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
    	return getCertificateRequest(new AdminInfo("CLI user", null, null), signerId, certReqInfo,
    			explicitEccParameters, defaultKey);
    }
    
    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#getCertificateRequest(int, org.signserver.common.ISignerCertReqInfo)
     */
    @Override
    public ICertReqData getCertificateRequest(final AdminInfo adminInfo, WorkerIdentifier signerId,
            ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters,
            final boolean defaultKey) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
        return getCertificateRequestInternal(adminInfo, signerId, certReqInfo,
                explicitEccParameters, null, defaultKey);
    }
    
    private ICertReqData getCertificateRequestInternal(final AdminInfo adminInfo, WorkerIdentifier signerId,
            ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters,
            final String keyAlias,
            final boolean defaultKey)
        throws CryptoTokenOfflineException, InvalidWorkerIdException {
        try {
            if (LOG.isTraceEnabled()) {
                LOG.trace(">getCertificateRequest: signerId=" + signerId);
            }
            IWorker worker = workerManagerSession.getWorker(signerId);
            
            if (!(worker instanceof IProcessable)) {
                throw new InvalidWorkerIdException(
                        "Worker exists but isn't a signer.");
            }
            IProcessable processable = (IProcessable) worker;
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found processable worker of type: " + processable.
                        getClass().getName());
            }
            
            final ICertReqData ret;
            try {
                if (keyAlias != null) {
                    ret = processable.genCertificateRequest(certReqInfo,
                            explicitEccParameters, keyAlias, servicesImpl);
                } else {
                    ret = processable.genCertificateRequest(certReqInfo,
                            explicitEccParameters, defaultKey, servicesImpl);
                }
            } catch (NoSuchAliasException ex) {
                throw new CryptoTokenOfflineException("No such alias: " + ex.getMessage(), ex);
            }
            
            final HashMap<String, Object> auditMap = new HashMap<>();
            
            String csr = null;
            try {
                if (ret instanceof AbstractCertReqData) {
                    csr = org.bouncycastle.util.encoders.Base64.toBase64String(((AbstractCertReqData) ret).toBinaryForm());
                } else if (ret instanceof Base64SignerCertReqData) {
                    csr = new String(((Base64SignerCertReqData) ret).getBase64CertReq());
                } else if (ret != null) {
                    csr = ret.toString();
                }
            } catch (IOException ex) {
                LOG.error("Unable to encode CSR", ex);
            }
            
            final WorkerConfig config = processable.getConfig();
            
            auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), keyAlias == null && defaultKey ? config.getProperty("DEFAULTKEY") : keyAlias);
            auditMap.put(AdditionalDetailsTypes.FOR_DEFAULTKEY.name(), String.valueOf(defaultKey));
            auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(signerId, config));
            if (csr != null) {
                auditMap.put(AdditionalDetailsTypes.CSR.name(), csr);
            }
            auditLog(adminInfo, SignServerEventTypes.GENCSR, EventStatus.SUCCESS, SignServerModuleTypes.KEY_MANAGEMENT, signerId, auditMap);
            
            if (LOG.isTraceEnabled()) {
                LOG.trace("<getCertificateRequest: signerId=" + signerId);
            }
            return ret;
        } catch (NoSuchWorkerException ex) {
            throw new InvalidWorkerIdException(ex.getMessage());
        }
    }

    @Override
    public ICertReqData getCertificateRequest(AdminInfo adminInfo, WorkerIdentifier signerId,
            ISignerCertReqInfo certReqInfo, boolean explicitEccParameters,
            String keyAlias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException {
        return getCertificateRequestInternal(adminInfo, signerId, certReqInfo,
                explicitEccParameters, keyAlias, false);
    }

    @Override
    public ICertReqData getCertificateRequest(WorkerIdentifier signerId,
            ISignerCertReqInfo certReqInfo, boolean explicitEccParameters,
            String keyAlias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException {
        return getCertificateRequest(new AdminInfo("CLI user", null, null),
                signerId, certReqInfo, explicitEccParameters, keyAlias);
    }
    
    

    @Override
    public Certificate getSignerCertificate(final WorkerIdentifier signerId) throws CryptoTokenOfflineException {
        Certificate ret = null;
        try {
            final IWorker worker = workerManagerSession.getWorker(signerId);
            if (worker instanceof BaseProcessable) {
                final BaseProcessable processable = (BaseProcessable) worker;
                
                ret = processable.getSigningCertificate(servicesImpl);
            }
        } catch (NoSuchWorkerException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No such worker: " + ex.getMessage());
            }
        }
        return ret;
    }

    @Override
    public List<Certificate> getSignerCertificateChain(final WorkerIdentifier signerId)
            throws CryptoTokenOfflineException {
        List<Certificate> ret = null;
        try {
            IWorker worker = workerManagerSession.getWorker(signerId);
            if (worker instanceof BaseProcessable) {
                final BaseProcessable processable = (BaseProcessable) worker;
                
                ret = processable.getSigningCertificateChain(servicesImpl);
            }
        } catch (NoSuchWorkerException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No such worker: " + ex.getMessage());
            }
        }
        return ret;
    }
    
    @Override
    public byte[] getSignerCertificateBytes(final WorkerIdentifier signerId) 
            throws CryptoTokenOfflineException {
        try {
            final Certificate cert = getSignerCertificate(signerId);
            return cert == null ? null : cert.getEncoded();
        } catch (CertificateEncodingException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
    }

    @Override
    public List<byte[]> getSignerCertificateChainBytes(final WorkerIdentifier signerId)
            throws CryptoTokenOfflineException {
        final List<Certificate> certs = getSignerCertificateChain(signerId);
        final List<byte[]> res = new LinkedList<>();
        
        if (certs == null) {
            return null;
        }
        
        try {
            for (Certificate cert : certs) {
                res.add(cert.getEncoded());
            }
        } catch (CertificateEncodingException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
        return res;
    }

    @Override
    public List<Certificate> getSigningCertificateChain(final AdminInfo adminInfo,
                                                        final WorkerIdentifier signerId,
                                                        final String alias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException {
        List<Certificate> ret = null;
        try {
            final IWorker worker = workerManagerSession.getWorker(signerId);
            if (worker instanceof BaseProcessable) {
                ret = ((BaseProcessable) worker).getSigningCertificateChain(alias, servicesImpl);
            }
        } catch (NoSuchWorkerException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No such worker: " + ex.getMessage());
            }
        }
        return ret;
    }

    @Override
    public List<Certificate> getSignerCertificateChain(final WorkerIdentifier signerId,
                                                       final String alias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException {
        return getSigningCertificateChain(new AdminInfo("CLI user", null, null),
                                         signerId, alias);
    }
    
    
    
    @Override
    public boolean removeKey(final AdminInfo adminInfo, final WorkerIdentifier signerId, final String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
        try {
            IWorker worker = workerManagerSession.getWorker(signerId);
            final boolean result;
            if (!(worker instanceof IProcessable)) {
                throw new InvalidWorkerIdException(
                        "Worker exists but isn't a signer.");
            }
            IProcessable signer = (IProcessable) worker;
            result = signer.removeKey(alias, servicesImpl);
        
            final HashMap<String, Object> auditMap = new HashMap<>();
            auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), alias);
            auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(signerId, worker.getConfig()));
            auditMap.put(AdditionalDetailsTypes.SUCCESS.name(), String.valueOf(result));
            auditLog(adminInfo, SignServerEventTypes.KEYREMOVE, EventStatus.SUCCESS, SignServerModuleTypes.KEY_MANAGEMENT, signerId, auditMap);
            
            return result;
        } catch (NoSuchWorkerException ex) {
            throw new InvalidWorkerIdException(ex.getMessage());
        }
    }
    
    @Override
    public boolean removeKey(final WorkerIdentifier signerId, final String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
        return removeKey(new AdminInfo("CLI user", null, null), signerId, alias);
    }

    @Override
    public void uploadSignerCertificate(int signerId, byte[] signerCert,
            String scope) throws CertificateException {
    	uploadSignerCertificate(new AdminInfo("CLI user", null, null), signerId, signerCert, scope);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#uploadSignerCertificate(int, java.security.cert.X509Certificate, java.lang.String)
     */
    @Override
    public void uploadSignerCertificate(final AdminInfo adminInfo, int signerId, byte[] signerCert,
            String scope) throws CertificateException {
        WorkerConfig config = getWorkerConfig(signerId);

        final Certificate cert  = CertTools.getCertfromByteArray(signerCert);
        config.setSignerCertificate((X509Certificate)cert,scope);
        setWorkerConfig(adminInfo, signerId, config, null, null);
        final boolean scopeGlobal = GlobalConfiguration.SCOPE_GLOBAL.equalsIgnoreCase(scope);
        auditLogCertInstalled(adminInfo, new WorkerIdentifier(signerId), new String (CertTools.getPEMFromCerts(Arrays.asList(cert))), scopeGlobal ? "GLOBAL" : "NODE", scopeGlobal ? null : WorkerConfig.getNodeId());
    }

    @Override
    public void uploadSignerCertificateChain(int signerId, List<byte[]> signerCerts, String scope)
    	throws CertificateException {
    	uploadSignerCertificateChain(new AdminInfo("CLI user", null, null), signerId, signerCerts, scope);
    }
    
    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#uploadSignerCertificateChain(int, java.util.Collection, java.lang.String)
     */
    @Override
    public void uploadSignerCertificateChain(final AdminInfo adminInfo, int signerId, List<byte[]> signerCerts, String scope) 
            throws CertificateException {

        WorkerConfig config = getWorkerConfig(signerId);
    	ArrayList<Certificate> certs = new ArrayList<>();
    	Iterator<byte[]> iter = signerCerts.iterator();
    	while(iter.hasNext()){
            X509Certificate cert;
            cert = (X509Certificate) CertTools.getCertfromByteArray(iter.next());
            certs.add(cert);
    	}
    	// Collections.reverse(certs); // TODO: Why?

        config.setSignerCertificateChain(certs, scope);
        setWorkerConfig(adminInfo, signerId, config, null, null);
        final boolean scopeGlobal = GlobalConfiguration.SCOPE_GLOBAL.equalsIgnoreCase(scope);
        auditLogCertChainInstalled(adminInfo, new WorkerIdentifier(signerId), new String (CertTools.getPEMFromCerts(certs)), scopeGlobal ? "GLOBAL" : "NODE", scopeGlobal ? null : WorkerConfig.getNodeId());
    }

    @Override
    public void importCertificateChain(final AdminInfo adminInfo, final WorkerIdentifier signerId,
                                       final List<byte[]> signerCerts,
                                       final String alias,
                                       final char[] authenticationCode)
            throws CryptoTokenOfflineException, CertificateException,
                   OperationUnsupportedException {
        try {
            final List<Certificate> certs = new LinkedList<>();
            
            for (final byte[] certBytes : signerCerts) {
                final X509Certificate cert =
                        (X509Certificate) CertTools.getCertfromByteArray(certBytes);
                certs.add(cert);
            }
            
            final IWorker worker = workerManagerSession.getWorker(signerId);
            
            if (worker instanceof IProcessable) {
                try {
                    ((IProcessable) worker).importCertificateChain(certs, alias, authenticationCode, Collections.<String, Object>emptyMap(), servicesImpl);
                    auditLogCertChainInstalledToToken(adminInfo, EventStatus.SUCCESS, signerId, worker.getConfig(), alias, new String(CertTools.getPEMFromCerts(certs)), null);
                } catch (NoSuchAliasException ex) {
                    auditLogCertChainInstalledToToken(adminInfo, EventStatus.FAILURE, signerId, worker.getConfig(), alias, new String(CertTools.getPEMFromCerts(certs)), ex.getMessage());
                    throw new CryptoTokenOfflineException("No such alias: " + ex.getLocalizedMessage());
                } catch (InvalidAlgorithmParameterException | UnsupportedCryptoTokenParameter ex) {
                    auditLogCertChainInstalledToToken(adminInfo, EventStatus.FAILURE, signerId, worker.getConfig(), alias, new String(CertTools.getPEMFromCerts(certs)), ex.getMessage());
                    throw new CryptoTokenOfflineException(ex);
                } catch (CryptoTokenOfflineException ex) {
                    auditLogCertChainInstalledToToken(adminInfo, EventStatus.FAILURE, signerId, worker.getConfig(), alias, new String(CertTools.getPEMFromCerts(certs)), ex.getMessage());
                    throw ex;
                }
            } else {
                auditLogCertChainInstalledToToken(adminInfo, EventStatus.FAILURE, signerId, worker.getConfig(), alias, new String(CertTools.getPEMFromCerts(certs)), "Import not supported by worker");
                throw new OperationUnsupportedException("Import not supported by worker");
            }
        } catch (NoSuchWorkerException ex) {
            throw new OperationUnsupportedException(ex.getMessage());
        }
    }

    @Override
    public void importCertificateChain(final WorkerIdentifier signerId,
                                       final List<byte[]> signerCerts,
                                       final String alias,
                                       final char[] authenticationCode)
            throws CryptoTokenOfflineException, CertificateException,
                   OperationUnsupportedException {
        importCertificateChain(new AdminInfo("CLI user", null, null), signerId,
                signerCerts, alias, authenticationCode);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#genFreeWorkerId()
     */
    @Override
    public int genFreeWorkerId() {
        Collection<Integer> ids = getAllWorkers();
        int max = 0;
        Iterator<Integer> iter = ids.iterator();
        while (iter.hasNext()) {
            Integer id = iter.next();
            if (id > max) {
                max = id;
            }
        }

        return max + 1;
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#findArchiveDataFromArchiveId(int, java.lang.String)
     */
    @Override
    public List<ArchiveDataVO> findArchiveDataFromArchiveId(int signerId,
            String archiveId) {
        final LinkedList<ArchiveDataVO> result = new LinkedList<>();
        if (archiveDataService == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Archiving to database is not supported when running without database");
            }
        } else {
             final List list = archiveDataService.findAllByArchiveId(signerId, archiveId);
             for (Object o : list) {
                 if (o instanceof ArchiveDataBean) {
                     final ArchiveDataBean adb = (ArchiveDataBean) o;
                     result.add(adb.getArchiveDataVO());
                 }
             }
        }
        return result;
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#findArchiveDatasFromRequestIP(int, java.lang.String)
     */
    @Override
    public List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerId,
            String requestIP) {
        List<ArchiveDataVO> retval = new LinkedList<>();

        if (archiveDataService == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Archiving to database is not supported when running without database");
            }
        } else {
            Collection<ArchiveDataBean> archives = archiveDataService.findAllByRequestIP(signerId, requestIP);
            for (ArchiveDataBean archive : archives) {
                retval.add(archive.getArchiveDataVO());
            }
        }

        return retval;
    }
    
    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.WorkerSession#findArchiveDatasFromRequestCertificate(int, java.math.BigInteger, java.lang.String)
     */
    @Override
    public List<ArchiveDataVO> findArchiveDatasFromRequestCertificate(
            int signerId, BigInteger requestCertSerialnumber,
            String requestCertIssuerDN) {
        ArrayList<ArchiveDataVO> retval = new ArrayList<>();

        if (archiveDataService == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Archiving to database is not supported when running without database");
            }
        } else {
            String issuerDN = CertTools.stringToBCDNString(requestCertIssuerDN);
            String serialNumber = requestCertSerialnumber.toString(16);

            Collection<ArchiveDataBean> archives = archiveDataService.
                    findAllByRequestCertificate(signerId, issuerDN, serialNumber);
            for (ArchiveDataBean archive : archives) {
                retval.add(archive.getArchiveDataVO());
            }
        }

        return retval;
    }
    
    private WorkerConfig getWorkerConfig(int workerId) {
        return workerConfigService.getWorkerProperties(workerId, true);
    }

    private String generateTransactionID() {
        return UUID.randomUUID().toString();
    }
    
    @Override
    public List<Integer> getWorkers(WorkerType workerType) {
        return workerManagerSession.getAllWorkerIDs(workerType);
    }

    @Override
    public List<Integer> getAllWorkers() {
        return workerManagerSession.getAllWorkerIDs();
    }
    
    @Override
    public List<String> getAllWorkerNames() {
        return workerManagerSession.getAllWorkerNames();
    }
    
    private void auditLog(final AdminInfo adminInfo, SignServerEventTypes eventType, SignServerModuleTypes module,
    		final WorkerIdentifier wi) {
        auditLog(adminInfo, eventType, EventStatus.SUCCESS, module, wi, Collections.<String, Object>emptyMap());
    }
    
    private void auditLog(final AdminInfo adminInfo, SignServerEventTypes eventType, EventStatus outcome, SignServerModuleTypes module, final WorkerIdentifier wi, Map<String, Object> additionalDetails) {
        try {
        	final String serialNo =
        			adminInfo.getCertSerialNumber() == null ? null : adminInfo.getCertSerialNumber().toString(16);
            logSession.log(eventType, outcome, module, SignServerServiceTypes.SIGNSERVER,
                    adminInfo.getSubjectDN(), adminInfo.getIssuerDN(), serialNo, wi.hasId() ? String.valueOf(wi.getId()) : wi.getName(), additionalDetails);

        } catch (AuditRecordStorageException ex) {
            LOG.error("Audit log failure", ex);
            throw new EJBException("Audit log failure", ex);
        }
    }
    
    /**
     * Helper method that changes masked properties to prevent a possible
     * side-channel where a user could guess a masked property by setting
     * a new value and see it showed up as changed in the auditlog.
     * 
     * @param config 
     */
    private static void scrambleMaskedProperties(final WorkerConfig config) {
       for (final Object o : config.getProperties().keySet()) {
           final String key = (String) o;
           
           if (config.shouldMaskProperty(key)) {
               config.getProperties().setProperty(key, "_OLD_MASKED_");
           }
       } 
    }

    private void setWorkerConfig(final AdminInfo adminInfo, final int workerId, final WorkerConfig config,
    		final String additionalLogKey, final String additionalLogValue) {
        final WorkerConfig oldConfig = workerConfigService.getWorkerProperties(workerId, true);
        
        scrambleMaskedProperties(oldConfig);

        Map<String, Object> configChanges = config.propertyDiffAgainst(oldConfig);
        
        if (additionalLogKey != null) {
        	configChanges.put(additionalLogKey, additionalLogValue);
        }
        
        auditLog(adminInfo, SignServerEventTypes.SET_WORKER_CONFIG, EventStatus.SUCCESS, SignServerModuleTypes.WORKER_CONFIG,
        		new WorkerIdentifier(workerId), configChanges);
        workerConfigService.setWorkerConfig(workerId, config);
    }

    private String createResultsReport(final Collection<KeyTestResult> results) {
        final StringBuilder buff = new StringBuilder();
        final Iterator<KeyTestResult> it = results.iterator();
        
        while (it.hasNext()) {
            final KeyTestResult result = it.next();
            buff.append(result.toString());
            if (it.hasNext()) {
                buff.append(", ");
            }
        }
        return buff.toString();
    }

    @Override
    public List<? extends AuditLogEntry> selectAuditLogs(AdminInfo adminInfo, int startIndex, int max, QueryCriteria criteria, String logDeviceId) throws AuthorizationDeniedException {
        return auditorSession.selectAuditLogs(new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(adminInfo.getSubjectDN())), startIndex, max, criteria, logDeviceId);
    }

    @Override
    public List<? extends AuditLogEntry> selectAuditLogs(int startIndex, int max, QueryCriteria criteria, String logDeviceId) throws AuthorizationDeniedException {
        return selectAuditLogs(new AdminInfo("CLI user", null, null), startIndex, max, criteria, logDeviceId);
    }

    @Override
    public List<ArchiveMetadata> searchArchive(final int startIndex, final int max,
            final QueryCriteria criteria, final boolean includeData) {
        return searchArchive(new AdminInfo("CLI user", null, null), startIndex,
                max, criteria, includeData);
    }

    @Override
    public List<ArchiveMetadata> searchArchive(final AdminInfo adminInfo,
            final int startIndex, final int max, final QueryCriteria criteria,
            final boolean includeData) {
        if (archiveDataService == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Archiving to database is not supported when running without database");
            }
            return Collections.emptyList();
        } else {
            return archiveDataService.findMatchingCriteria(startIndex, max, criteria, includeData);
        }
    }

    @Override
    public List<ArchiveMetadata> searchArchiveWithIds(AdminInfo adminInfo,
        List<String> uniqueIds, boolean includeData) {
        if (archiveDataService == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Archiving to database is not supported when running without database");
            }
            return Collections.emptyList();
        } else {
            return archiveDataService.findAllWithUniqueIdInList(uniqueIds, includeData);
        }
    }

    @Override
    public List<ArchiveMetadata> searchArchiveWithIds(List<String> uniqueIds,
        boolean includeData) throws AuthorizationDeniedException {
        return searchArchiveWithIds(new AdminInfo("CLI user", null, null),
                uniqueIds, includeData);
    }

    private void initKeyUsageCounter(final IWorker worker, final IServices services) {
        // Try to insert a key usage counter entry for this worker's public
        // key
        // Get worker instance
        if (worker instanceof BaseProcessable) {
            try {
                final Certificate cert = ((BaseProcessable)worker)
                        .getSigningCertificate(services);
                if (cert != null) {
                    final String keyHash = KeyUsageCounterHash
                            .create(cert.getPublicKey());

                    KeyUsageCounter counter
                            = keyUsageCounterDataService.getCounter(keyHash);

                    if (counter == null) {
                        keyUsageCounterDataService.create(keyHash);
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Worker[" + worker.getConfig().getProperty("NAME") + "]: "
                                    + "new key usage counter initialized");
                        }
                    } else {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Worker[" + worker.getConfig().getProperty("NAME") + "]: "
                                    + "key usage counter: " + counter.getCounter());
                        }
                    }
                }
            } catch (CryptoTokenOfflineException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Worker[ " + worker.getConfig().getProperty("NAME") + "]: "
                        + "Crypto token offline trying to create key usage counter");
                }
            }
        }
    }

    @Override
    public TokenSearchResults searchTokenEntries(final WorkerIdentifier workerId, int startIndex, int max, final QueryCriteria qc, final boolean includeData, final Map<String, Object> params) throws
            InvalidWorkerIdException,
            AuthorizationDeniedException,
            CryptoTokenOfflineException,
            QueryException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            OperationUnsupportedException {
        return searchTokenEntries(new AdminInfo("CLI user", null, null), workerId, startIndex, max, qc, includeData, params);
    }
    
    @Override
    public TokenSearchResults searchTokenEntries(final AdminInfo adminInfo, final WorkerIdentifier workerId, int startIndex, int max, final QueryCriteria qc, final boolean includeData, final Map<String, Object> params) throws
            InvalidWorkerIdException,
            AuthorizationDeniedException,
            CryptoTokenOfflineException,
            QueryException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            OperationUnsupportedException {
        try {
            final IWorker worker = workerManagerSession.getWorker(workerId);
            if (worker instanceof IProcessable) {
                return ((IProcessable) worker).searchTokenEntries(startIndex, max, qc, includeData, params, servicesImpl);
            } else {
                throw new OperationUnsupportedException("Operation not supported by worker");
            }
        } catch (NoSuchWorkerException ex) {
            throw new InvalidWorkerIdException(ex.getMessage());
        }
    }

    @Override
    public List<String> getCertificateIssues(int workerId, List<Certificate> certificateChain) throws InvalidWorkerIdException {
        try {
            final IWorker worker = workerManagerSession.getWorker(new WorkerIdentifier(workerId));
            if (worker instanceof IProcessable) {
                IProcessable processable = (IProcessable) worker;
                return processable.getCertificateIssues(certificateChain);
            } else {
                return Collections.emptyList();
            }
        } catch (NoSuchWorkerException ex) {
            throw new InvalidWorkerIdException(ex.getMessage());
        }
    }

    @Override
    public boolean isKeyGenerationDisabled() {
        return SignServerUtil.isKeyGenerationDisabled();
    }  
}
