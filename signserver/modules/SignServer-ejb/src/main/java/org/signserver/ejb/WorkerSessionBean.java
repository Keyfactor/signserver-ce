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
import org.signserver.common.*;
import org.signserver.common.KeyTestResult;
import org.signserver.common.util.PropertiesConstants;
import org.signserver.ejb.interfaces.IDispatcherWorkerSession;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IInternalWorkerSession;
import org.signserver.ejb.interfaces.IServiceTimerSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.ejb.worker.impl.IWorkerManagerSessionLocal;
import org.signserver.server.*;
import org.signserver.server.archive.olddbarchiver.entities.ArchiveDataBean;
import org.signserver.server.archive.olddbarchiver.entities.ArchiveDataService;
import org.signserver.server.cesecore.AlwaysAllowLocalAuthenticationToken;
import org.signserver.server.config.entities.FileBasedWorkerConfigDataService;
import org.signserver.server.config.entities.IWorkerConfigDataService;
import org.signserver.server.config.entities.WorkerConfigDataService;
import org.signserver.common.DuplicateAliasException;
import org.signserver.server.cryptotokens.IKeyRemover;
import org.signserver.common.NoSuchAliasException;
import org.signserver.server.cryptotokens.TokenSearchResults;
import org.signserver.common.UnsupportedCryptoTokenParameter;
import org.signserver.server.entities.FileBasedKeyUsageCounterDataService;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounter;
import org.signserver.server.entities.KeyUsageCounterDataService;
import org.signserver.server.log.*;
import org.signserver.server.nodb.FileBasedDatabaseManager;
import org.signserver.server.statistics.StatisticsManager;
import org.signserver.statusrepo.IStatusRepositorySession;

/**
 * The main worker session bean.
 * 
 * @version $Id$
 */
@Stateless
public class WorkerSessionBean implements IWorkerSession.ILocal,
        IWorkerSession.IRemote {
    
    /** Log4j instance for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerSessionBean.class);
   
    /** The local home interface of Worker Config entity bean. */
    private IWorkerConfigDataService workerConfigService;
    
    /** The local home interface of archive entity bean. */
    private ArchiveDataService archiveDataService;
    
    private IKeyUsageCounterDataService keyUsageCounterDataService;

    @EJB
    private IGlobalConfigurationSession.ILocal globalConfigurationSession;

    @EJB
    private IServiceTimerSession.ILocal serviceTimerSession;
    
    @EJB
    private IWorkerManagerSessionLocal workerManagerSession;
    
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    @EJB
    private SecurityEventsAuditorSessionLocal auditorSession;
    
    @Resource
    private SessionContext ctx;
    
    EntityManager em;

    private WorkerProcessImpl processImpl;
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
        processImpl = new WorkerProcessImpl(em, keyUsageCounterDataService, globalConfigurationSession, workerManagerSession, logSession);

        // XXX The lookups will fail on GlassFish V2
        // When we no longer support GFv2 we can refactor this code
        IInternalWorkerSession.ILocal internalSession = null;
        IDispatcherWorkerSession.ILocal dispatcherSession = null;
        IStatusRepositorySession.ILocal statusSession = null;
        try {
            internalSession = ServiceLocator.getInstance().lookupLocal(IInternalWorkerSession.ILocal.class);
            dispatcherSession = ServiceLocator.getInstance().lookupLocal(IDispatcherWorkerSession.ILocal.class);
            statusSession = ServiceLocator.getInstance().lookupLocal(IStatusRepositorySession.ILocal.class);
        } catch (NamingException ex) {
            LOG.error("Lookup services failed. This is expected on GlassFish V2: " + ex.getExplanation());
            if (LOG.isDebugEnabled()) {
                LOG.debug("Lookup services failed", ex);
            }
        }
        // Add all services
        servicesImpl.putAll(
                em,
                ctx.getBusinessObject(IWorkerSession.ILocal.class),
                globalConfigurationSession,
                logSession, 
                internalSession, dispatcherSession, statusSession);
    }

    @Override
    public ProcessResponse process(final int workerId,
            final ProcessRequest request, final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {
        requestContext.setServices(servicesImpl);
        return processImpl.process(workerId, request, requestContext);
    }
    
    @Override
    public ProcessResponse process(final AdminInfo adminInfo, final int workerId,
            final ProcessRequest request, final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {
        requestContext.setServices(servicesImpl);
        if (LOG.isDebugEnabled()) {
            LOG.debug(">process: " + workerId);
        }
        return processImpl.process(adminInfo, workerId, request, requestContext);
    }

    /**
     * Gets the last date the specified worker can do signings.
     * @param workerId Id of worker to check.
     * @return The last date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
    @Override
    public Date getSigningValidityNotAfter(final int workerId)
            throws CryptoTokenOfflineException {
        Date date = null;
        final Certificate signerCert = getSignerCertificate(workerId);
        if (signerCert instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate) signerCert;
            date = ValidityTimeUtils.getSigningValidity(true, workerId,
                    getWorkerConfig(workerId), cert);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Worker does not have a signing certificate. Worker: "
                        + workerId);
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
    public Date getSigningValidityNotBefore(final int workerId)
            throws CryptoTokenOfflineException {
        Date date = null;
        final Certificate signerCert = getSignerCertificate(workerId);
        if (signerCert instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate) signerCert;
            date = ValidityTimeUtils.getSigningValidity(false, workerId,
                    getWorkerConfig(workerId), cert);
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
    public long getKeyUsageCounterValue(final int workerId) 
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
     * @see org.signserver.ejb.interfaces.IWorkerSession#getStatus(int)
     */
    @Override
    public WorkerStatus getStatus(int workerId) throws InvalidWorkerIdException {
        IWorker worker = workerManagerSession.getWorker(workerId, globalConfigurationSession);
        if (worker == null) {
            throw new InvalidWorkerIdException("Given SignerId " + workerId
                    + " doesn't exist");
        }
        final List<String> errorsAtEjbLevel = new LinkedList<String>();
        if (worker instanceof IProcessable) {
            final IProcessable processable = (IProcessable) worker;
            try {
                final IAuthorizer authenticator = workerManagerSession.getAuthenticator(
                        workerId, processable.getAuthenticationType(), worker.getConfig());
                errorsAtEjbLevel.addAll(authenticator.getFatalErrors());
            } catch (IllegalRequestException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unable to get authenticator for worker: " + workerId, ex);
                }
                errorsAtEjbLevel.add(ex.getLocalizedMessage());
            }
        }
        return worker.getStatus(errorsAtEjbLevel, servicesImpl);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#getWorkerId(java.lang.String)
     */
    @Override
    public int getWorkerId(String signerName) {
        return workerManagerSession.getIdFromName(signerName, globalConfigurationSession);
    }
   
    @Override
    public void reloadConfiguration(int workerId) {
        reloadConfiguration(new AdminInfo("CLI user", null, null), workerId);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession.ILocal#reloadConfiguration(adminInfo, int)
     */
    @Override
    public void reloadConfiguration(final AdminInfo adminInfo, int workerId) {
        if (workerId == 0) {
            globalConfigurationSession.reload(adminInfo);
        } else {
            workerManagerSession.reloadWorker(workerId, globalConfigurationSession);
            auditLog(adminInfo, SignServerEventTypes.RELOAD_WORKER_CONFIG, EventStatus.SUCCESS, SignServerModuleTypes.WORKER_CONFIG,
                    Integer.toString(workerId), Collections.<String, Object>emptyMap());

            // Try to initialize the key usage counter
            initKeyUsageCounter(workerManagerSession.getWorker(workerId,
                                                               globalConfigurationSession),
                                null, null);
        }

        if (workerId == 0 || getWorkers(
                GlobalConfiguration.WORKERTYPE_SERVICES).contains(
                workerId)) {
            serviceTimerSession.unload(workerId);
            serviceTimerSession.load(workerId);
        }

        StatisticsManager.flush(workerId);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#activateSigner(int, java.lang.String)
     */
    @Override
    public void activateSigner(int signerId, String authenticationCode)
            throws CryptoTokenAuthenticationFailureException,
            CryptoTokenOfflineException, InvalidWorkerIdException {
        IWorker worker = workerManagerSession.getWorker(signerId, globalConfigurationSession);
        if (worker == null) {
            throw new InvalidWorkerIdException("Given SignerId " + signerId
                    + " doesn't exist");
        }

        if (!(worker instanceof IProcessable)) {
            throw new InvalidWorkerIdException(
                    "Worker exists but isn't a signer.");
        }
        IProcessable signer = (IProcessable) worker;

        signer.activateSigner(authenticationCode);

        // Try to initialize the key usage counter
        initKeyUsageCounter(worker, null, null);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#deactivateSigner(int)
     */
    @Override
    public boolean deactivateSigner(int signerId)
            throws CryptoTokenOfflineException, InvalidWorkerIdException {
        IWorker worker = workerManagerSession.getWorker(signerId, globalConfigurationSession);
        if (worker == null) {
            throw new InvalidWorkerIdException("Given SignerId " + signerId
                    + " doesn't exist");
        }

        if (!(worker instanceof IProcessable)) {
            throw new InvalidWorkerIdException(
                    "Worker exists but isn't a signer.");
        }
        IProcessable signer = (IProcessable) worker;

        return signer.deactivateSigner();
    }

    @Override
    public String generateSignerKey(final int signerId, String keyAlgorithm,
            String keySpec, String alias, final char[] authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
                IllegalArgumentException {
    	return generateSignerKey(new AdminInfo("CLI user", null, null), signerId, keyAlgorithm,
    			keySpec, alias, authCode);
    }

    @Override
    public String generateSignerKey(final AdminInfo adminInfo, final int signerId, String keyAlgorithm,
            String keySpec, String alias, final char[] authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
                IllegalArgumentException {

        IWorker worker = workerManagerSession.getWorker(signerId, globalConfigurationSession);
        if (worker == null) {
            throw new InvalidWorkerIdException("Given SignerId " + signerId
                    + " doesn't exist");
        }

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
                alias = nextAliasInSequence(currentAlias);
            }
        }

        try {
            signer.generateKey(keyAlgorithm, keySpec, alias, authCode, Collections.<String, Object>emptyMap(),
                    servicesImpl);
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
        }
        
        final HashMap<String, Object> auditMap = new HashMap<String, Object>();
        auditMap.put(AdditionalDetailsTypes.KEYALG.name(), keyAlgorithm);
        auditMap.put(AdditionalDetailsTypes.KEYSPEC.name(), keySpec);
        auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), alias);
        auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(signerId, config));
        auditLog(adminInfo, SignServerEventTypes.KEYGEN, EventStatus.SUCCESS, SignServerModuleTypes.KEY_MANAGEMENT, String.valueOf(signerId), auditMap);
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

    static String nextAliasInSequence(final String currentAlias) {

        String prefix = currentAlias;
        String nextSequence = "2";

        final String[] entry = currentAlias.split("[0-9]+$");
        if (entry.length == 1) {
            prefix = entry[0];
            final String currentSequence
                    = currentAlias.substring(prefix.length());
            final int sequenceChars = currentSequence.length();
            if (sequenceChars > 0) {
                final long nextSequenceNumber = Long.parseLong(currentSequence) + 1;
                final String nextSequenceNumberString
                        = String.valueOf(nextSequenceNumber);
                if (sequenceChars > nextSequenceNumberString.length()) {
                    nextSequence = currentSequence.substring(0,
                            sequenceChars - nextSequenceNumberString.length())
                            + nextSequenceNumberString;
                } else {
                    nextSequence = nextSequenceNumberString;
                }
            }
        }

        return prefix + nextSequence;
    }

    @Override
    public Collection<KeyTestResult> testKey(final int signerId, String alias,
            char[] authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            KeyStoreException {
    	return testKey(new AdminInfo("CLI user", null, null), signerId, alias, authCode);
    }
    
    @Override
    public Collection<KeyTestResult> testKey(final AdminInfo adminInfo, final int signerId, String alias,
            char[] authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            KeyStoreException {

        IWorker worker = workerManagerSession.getWorker(signerId, globalConfigurationSession);
        if (worker == null) {
            throw new InvalidWorkerIdException("Given SignerId " + signerId
                    + " doesn't exist");
        }

        if (!(worker instanceof IProcessable)) {
            throw new InvalidWorkerIdException(
                    "Worker exists but isn't a signer.");
        }
        final IProcessable signer = (IProcessable) worker;

        final WorkerConfig config = worker.getConfig();

        if (alias == null) {
            alias = config.getProperty("DEFAULTKEY");
        }
        
        final Collection<KeyTestResult> result = signer.testKey(alias, authCode, servicesImpl);

        final HashMap<String, Object> auditMap = new HashMap<String, Object>();
        auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), alias);
        auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(signerId, config));
        auditMap.put(AdditionalDetailsTypes.TESTRESULTS.name(), createResultsReport(result));
        auditLog(adminInfo, SignServerEventTypes.KEYTEST, EventStatus.SUCCESS, SignServerModuleTypes.KEY_MANAGEMENT, String.valueOf(signerId), auditMap);
        
        return result;
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.IWorkerSession#getCurrentSignerConfig(int)
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
    public byte[] getKeystoreData(AdminInfo adminInfo, int signerId) {
        WorkerConfig config = getWorkerConfig(signerId);
        
        return (new ProcessableConfig(config)).getKeystoreData();
    }

    @Override
    public void setKeystoreData(AdminInfo adminInfo, int signerId, byte[] keystoreData) {
        WorkerConfig config = getWorkerConfig(signerId);
        (new ProcessableConfig(config)).setKeystoreData(keystoreData);
        setWorkerConfig(adminInfo, signerId, config, "set:keystore_data", null);
    }
    
    
    
    
    @Override
    public void setWorkerProperty(int workerId, String key, String value) {
    	setWorkerProperty(new AdminInfo("CLI user", null, null), workerId, key, value);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#setWorkerProperty(int, java.lang.String, java.lang.String)
     */
    @Override
    public void setWorkerProperty(final AdminInfo adminInfo, int workerId, String key, String value) {
        WorkerConfig config = getWorkerConfig(workerId);
        config.setProperty(key.toUpperCase(), value);
        setWorkerConfig(adminInfo, workerId, config, null, null);
        auditLogWorkerPropertyChange(adminInfo, workerId, config, key, value);
    }
    
    private void auditLogCertInstalled(final AdminInfo adminInfo, final int workerId, final String value, final String scope, final String node) {
        final HashMap<String, Object> auditMap = new HashMap<String, Object>();
        auditMap.put(AdditionalDetailsTypes.CERTIFICATE.name(), value);
        auditMap.put(AdditionalDetailsTypes.SCOPE.name(), scope);
        if ("NODE".equalsIgnoreCase(scope)) {
            auditMap.put(AdditionalDetailsTypes.NODE.name(), node);
        }
        auditLog(adminInfo, SignServerEventTypes.CERTINSTALLED, EventStatus.SUCCESS, SignServerModuleTypes.WORKER_CONFIG, String.valueOf(workerId), auditMap);
    }
    
    private void auditLogCertChainInstalled(final AdminInfo adminInfo, final int workerId, final String value, final String scope, final String node) {
        final HashMap<String, Object> auditMap = new HashMap<String, Object>();
        auditMap.put(AdditionalDetailsTypes.CERTIFICATECHAIN.name(), value);
        auditMap.put(AdditionalDetailsTypes.SCOPE.name(), scope);
        if ("NODE".equalsIgnoreCase(scope)) {
            auditMap.put(AdditionalDetailsTypes.NODE.name(), node);
        }
        auditLog(adminInfo, SignServerEventTypes.CERTCHAININSTALLED, EventStatus.SUCCESS, SignServerModuleTypes.WORKER_CONFIG, String.valueOf(workerId), auditMap);
    }
    
    private void auditLogCertChainInstalledToToken(final AdminInfo adminInfo, EventStatus outcome, final int workerId, final String alias, final String value, final String error) {
        final HashMap<String, Object> auditMap = new HashMap<String, Object>();
        auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), alias);
        auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(workerId, getWorkerConfig(workerId)));
        auditMap.put(AdditionalDetailsTypes.CERTIFICATECHAIN.name(), value);
        if (error != null) {
            auditMap.put(AdditionalDetailsTypes.ERROR.name(), error);
        }
        auditLog(adminInfo, SignServerEventTypes.CERTCHAININSTALLED, outcome, SignServerModuleTypes.KEY_MANAGEMENT, String.valueOf(workerId), auditMap);
    }
    
    @Override
    public boolean removeWorkerProperty(int workerId, String key) {
    	return removeWorkerProperty(new AdminInfo("CLI user", null, null), workerId, key);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#removeWorkerProperty(int, java.lang.String)
     */
    @Override
    public boolean removeWorkerProperty(final AdminInfo adminInfo, int workerId, String key) {
        final boolean result;
        WorkerConfig config = getWorkerConfig(workerId);

        result = config.removeProperty(key.toUpperCase());
        if (config.getProperties().size() == 0) {
            workerConfigService.removeWorkerConfig(workerId);
            LOG.debug("WorkerConfig is empty and therefore removed.");
            auditLog(adminInfo, SignServerEventTypes.SET_WORKER_CONFIG, SignServerModuleTypes.WORKER_CONFIG, String.valueOf(workerId));
        } else {
            setWorkerConfig(adminInfo, workerId, config, null, null);
        }
        auditLogWorkerPropertyChange(adminInfo, workerId, config, key, "");
        return result;
    }
    
    private void auditLogWorkerPropertyChange(final AdminInfo adminInfo, final int workerId, final WorkerConfig config, final String key, final String value) {
        if ("DEFAULTKEY".equalsIgnoreCase(key)) {
            final HashMap<String, Object> auditMap = new HashMap<String, Object>();
            auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), value);
            auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(workerId, config));
            auditMap.put(AdditionalDetailsTypes.SCOPE.name(), "GLOBAL");
            auditLog(adminInfo, SignServerEventTypes.KEYSELECTED, EventStatus.SUCCESS, SignServerModuleTypes.WORKER_CONFIG, String.valueOf(workerId), auditMap);
        } else if (key != null && key.lastIndexOf(".") != -1 && key.substring(key.lastIndexOf(".")).equalsIgnoreCase(".DEFAULTKEY")) {
            final HashMap<String, Object> auditMap = new HashMap<String, Object>();
            auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), value);
            auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(workerId, config));
            auditMap.put(AdditionalDetailsTypes.SCOPE.name(), "NODE");
            auditMap.put(AdditionalDetailsTypes.NODE.name(), key.substring(0, key.lastIndexOf(".")));
            auditLog(adminInfo, SignServerEventTypes.KEYSELECTED, EventStatus.SUCCESS, SignServerModuleTypes.WORKER_CONFIG, String.valueOf(workerId), auditMap);
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
     * @see org.signserver.ejb.interfaces.IWorkerSession#getAuthorizedClients(int)
     */
    @Override
    public Collection<AuthorizedClient> getAuthorizedClients(int signerId) {
        return new ProcessableConfig(getWorkerConfig(signerId)).
                getAuthorizedClients();
    }

    @Override
    public void addAuthorizedClient(int signerId, AuthorizedClient authClient) {
    	addAuthorizedClient(new AdminInfo("CLI user", null, null), signerId, authClient);
    }
    
    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#addAuthorizedClient(int, org.signserver.common.AuthorizedClient)
     */
    @Override
    public void addAuthorizedClient(final AdminInfo adminInfo, int signerId, AuthorizedClient authClient) {
        WorkerConfig config = getWorkerConfig(signerId);
        (new ProcessableConfig(config)).addAuthorizedClient(authClient);
        setWorkerConfig(adminInfo, signerId, config, "added:authorized_client",
        		"SN: " + authClient.getCertSN() + ", issuer DN: " + authClient.getIssuerDN());
    }

    @Override
    public boolean removeAuthorizedClient(int signerId, AuthorizedClient authClient) {
    	return removeAuthorizedClient(new AdminInfo("CLI user", null, null), signerId, authClient);
    }
    
    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#removeAuthorizedClient(int, org.signserver.common.AuthorizedClient)
     */
    @Override
    public boolean removeAuthorizedClient(final AdminInfo adminInfo, int signerId,
            AuthorizedClient authClient) {
        boolean result;
        WorkerConfig config = getWorkerConfig(signerId);


        result = (new ProcessableConfig(config)).removeAuthorizedClient(
                authClient);
        setWorkerConfig(adminInfo, signerId, config, "removed:authorized_client",
        		"SN: " + authClient.getCertSN() + ", issuer DN: " + authClient.getIssuerDN());
        return result;
    }

    @Override
    public ICertReqData getCertificateRequest(final int signerId,
            final ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
    	return getCertificateRequest(new AdminInfo("CLI user", null, null), signerId, certReqInfo,
    			explicitEccParameters);
    }
    
    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#getCertificateRequest(int, org.signserver.common.ISignerCertReqInfo)
     */
    @Override
    public ICertReqData getCertificateRequest(final AdminInfo adminInfo, final int signerId,
            final ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
        return getCertificateRequest(adminInfo, signerId, certReqInfo, 
                explicitEccParameters, true);
    }

    @Override
    public ICertReqData getCertificateRequest(int signerId,
            ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters,
            final boolean defaultKey) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
    	return getCertificateRequest(new AdminInfo("CLI user", null, null), signerId, certReqInfo,
    			explicitEccParameters, defaultKey);
    }
    
    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#getCertificateRequest(int, org.signserver.common.ISignerCertReqInfo)
     */
    @Override
    public ICertReqData getCertificateRequest(final AdminInfo adminInfo, int signerId,
            ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters,
            final boolean defaultKey) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
        return getCertificateRequestInternal(adminInfo, signerId, certReqInfo,
                explicitEccParameters, null, defaultKey);
    }
    
    private ICertReqData getCertificateRequestInternal(final AdminInfo adminInfo, int signerId,
            ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters,
            final String keyAlias,
            final boolean defaultKey)
        throws CryptoTokenOfflineException, InvalidWorkerIdException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getCertificateRequest: signerId=" + signerId);
        }
        IWorker worker = workerManagerSession.getWorker(signerId, globalConfigurationSession);
        if (worker == null) {
            throw new InvalidWorkerIdException("Given SignerId " + signerId
                    + " doesn't exist");
        }

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

        final HashMap<String, Object> auditMap = new HashMap<String, Object>();
        
        final String csr;
        if (ret instanceof Base64SignerCertReqData) {
            csr = new String(((Base64SignerCertReqData) ret).getBase64CertReq());
        } else {
            csr = ret.toString();
        }
        
        final WorkerConfig config = getWorkerConfig(signerId);
        
        auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), keyAlias == null && defaultKey ? config.getProperty("DEFAULTKEY") : keyAlias);
        auditMap.put(AdditionalDetailsTypes.FOR_DEFAULTKEY.name(), String.valueOf(defaultKey));
        auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(signerId, config));
        auditMap.put(AdditionalDetailsTypes.CSR.name(), csr);
        auditLog(adminInfo, SignServerEventTypes.GENCSR, EventStatus.SUCCESS, SignServerModuleTypes.KEY_MANAGEMENT, String.valueOf(signerId), auditMap);
        
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getCertificateRequest: signerId=" + signerId);
        }
        return ret;
    }

    @Override
    public ICertReqData getCertificateRequest(AdminInfo adminInfo, int signerId,
            ISignerCertReqInfo certReqInfo, boolean explicitEccParameters,
            String keyAlias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException {
        return getCertificateRequestInternal(adminInfo, signerId, certReqInfo,
                explicitEccParameters, keyAlias, false);
    }

    @Override
    public ICertReqData getCertificateRequest(int signerId,
            ISignerCertReqInfo certReqInfo, boolean explicitEccParameters,
            String keyAlias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException {
        return getCertificateRequest(new AdminInfo("CLI user", null, null),
                signerId, certReqInfo, explicitEccParameters, keyAlias);
    }
    
    

    @Override
    public Certificate getSignerCertificate(final int signerId) throws CryptoTokenOfflineException {
         return getSignerCertificate(signerId, null, null);
    }

    private Certificate getSignerCertificate(final int signerId,
                                            final ProcessRequest request,
                                            final RequestContext context)
            throws CryptoTokenOfflineException {
        Certificate ret = null;
        final IWorker worker = workerManagerSession.getWorker(signerId, globalConfigurationSession);
        if (worker instanceof BaseProcessable) {
            ret = ((BaseProcessable) worker).getSigningCertificate(request, context);
        }
        return ret;
    }

    @Override
    public List<Certificate> getSignerCertificateChain(final int signerId)
            throws CryptoTokenOfflineException {
        return getSignerCertificateChain(signerId, null, null);
    }
        
    private List<Certificate> getSignerCertificateChain(final int signerId,
                                                       final ProcessRequest request,
                                                       final RequestContext context)
            throws CryptoTokenOfflineException {
        List<Certificate> ret = null;
        IWorker worker = workerManagerSession.getWorker(signerId, globalConfigurationSession);
        if (worker instanceof BaseProcessable) {
            ret = ((BaseProcessable) worker).getSigningCertificateChain(request, context);
        }
        return ret;
    }
    
    @Override
    public byte[] getSignerCertificateBytes(final int signerId) 
            throws CryptoTokenOfflineException {
        return getSignerCertificateBytes(signerId, null, null);
    }
    
    private byte[] getSignerCertificateBytes(final int signerId,
                                            final ProcessRequest request,
                                            final RequestContext context) 
            throws CryptoTokenOfflineException {
        try {
            final Certificate cert =
                    getSignerCertificate(signerId, request, context);
            return cert == null ? null : cert.getEncoded();
        } catch (CertificateEncodingException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
    }

    @Override
    public List<byte[]> getSignerCertificateChainBytes(final int signerId)
            throws CryptoTokenOfflineException {
        return getSignerCertificateChainBytes(signerId, null, null);
    }
    
    public List<byte[]> getSignerCertificateChainBytes(final int signerId,
                                                       final ProcessRequest request,
                                                       final RequestContext context)
            throws CryptoTokenOfflineException {
        final List<Certificate> certs =
                getSignerCertificateChain(signerId, request, context);
        final List<byte[]> res = new LinkedList<byte[]>();
        
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
                                                        final int signerId,
                                                        final String alias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException {
        final IWorker worker = workerManagerSession.getWorker(signerId,
                                                              globalConfigurationSession);
        
        if (worker == null) {
            throw new InvalidWorkerIdException("Given SignerId " + signerId
                    + " doesn't exist");
        }
        
        List<Certificate> ret = null;
        
        if (worker instanceof BaseProcessable) {
            ret = ((BaseProcessable) worker).getSigningCertificateChain(alias);
        }
        
        return ret;
    }

    @Override
    public List<Certificate> getSignerCertificateChain(final int signerId,
                                                       final String alias)
            throws CryptoTokenOfflineException, InvalidWorkerIdException {
        return getSigningCertificateChain(new AdminInfo("CLI user", null, null),
                                         signerId, alias);
    }
    
    
    
    @Override
    public boolean removeKey(final AdminInfo adminInfo, final int signerId, final String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
        IWorker worker = workerManagerSession.getWorker(signerId, globalConfigurationSession);
        if (worker == null) {
            throw new InvalidWorkerIdException("Given SignerId " + signerId
                    + " doesn't exist");
        }
        final boolean result;
        if (worker instanceof IKeyRemover) {
            result = ((IKeyRemover) worker).removeKey(alias);
        } else {
            result = false;
        }
        final HashMap<String, Object> auditMap = new HashMap<String, Object>();
        auditMap.put(AdditionalDetailsTypes.KEYALIAS.name(), alias);
        auditMap.put(AdditionalDetailsTypes.CRYPTOTOKEN.name(), getCryptoToken(signerId, getWorkerConfig(signerId)));
        auditMap.put(AdditionalDetailsTypes.SUCCESS.name(), String.valueOf(result));
        auditLog(adminInfo, SignServerEventTypes.KEYREMOVE, EventStatus.SUCCESS, SignServerModuleTypes.KEY_MANAGEMENT, String.valueOf(signerId), auditMap);
        
        return result;
    }
    
    @Override
    public boolean removeKey(final int signerId, final String alias) throws CryptoTokenOfflineException, InvalidWorkerIdException, KeyStoreException, SignServerException {
        return removeKey(new AdminInfo("CLI user", null, null), signerId, alias);
    }

    @Override
    public void uploadSignerCertificate(int signerId, byte[] signerCert,
            String scope) throws CertificateException {
    	uploadSignerCertificate(new AdminInfo("CLI user", null, null), signerId, signerCert, scope);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#uploadSignerCertificate(int, java.security.cert.X509Certificate, java.lang.String)
     */
    @Override
    public void uploadSignerCertificate(final AdminInfo adminInfo, int signerId, byte[] signerCert,
            String scope) throws CertificateException {
        WorkerConfig config = getWorkerConfig(signerId);

        final Certificate cert  = CertTools.getCertfromByteArray(signerCert);
        ( new ProcessableConfig(config)).setSignerCertificate((X509Certificate)cert,scope);
        setWorkerConfig(adminInfo, signerId, config, null, null);
        final boolean scopeGlobal = GlobalConfiguration.SCOPE_GLOBAL.equalsIgnoreCase(scope);
        auditLogCertInstalled(adminInfo, signerId, new String (CertTools.getPEMFromCerts(Arrays.asList(cert))), scopeGlobal ? "GLOBAL" : "NODE", scopeGlobal ? null : WorkerConfig.getNodeId());
    }

    @Override
    public void uploadSignerCertificateChain(int signerId, Collection<byte[]> signerCerts, String scope)
    	throws CertificateException {
    	uploadSignerCertificateChain(new AdminInfo("CLI user", null, null), signerId, signerCerts, scope);
    }
    
    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#uploadSignerCertificateChain(int, java.util.Collection, java.lang.String)
     */
    @Override
    public void uploadSignerCertificateChain(final AdminInfo adminInfo, int signerId,
            Collection<byte[]> signerCerts, String scope) 
            throws CertificateException {

        WorkerConfig config = getWorkerConfig(signerId);
    	ArrayList<Certificate> certs = new ArrayList<Certificate>();
    	Iterator<byte[]> iter = signerCerts.iterator();
    	while(iter.hasNext()){
            X509Certificate cert;
            cert = (X509Certificate) CertTools.getCertfromByteArray(iter.next());
            certs.add(cert);
    	}
    	// Collections.reverse(certs); // TODO: Why?

        (new ProcessableConfig( config)).setSignerCertificateChain(certs, scope);
        setWorkerConfig(adminInfo, signerId, config, null, null);
        final boolean scopeGlobal = GlobalConfiguration.SCOPE_GLOBAL.equalsIgnoreCase(scope);
        auditLogCertChainInstalled(adminInfo, signerId, new String (CertTools.getPEMFromCerts(certs)), scopeGlobal ? "GLOBAL" : "NODE", scopeGlobal ? null : WorkerConfig.getNodeId());
    }

    @Override
    public void importCertificateChain(final AdminInfo adminInfo, final int signerId,
                                       final List<byte[]> signerCerts,
                                       final String alias,
                                       final char[] authenticationCode)
            throws CryptoTokenOfflineException, CertificateException,
                   OperationUnsupportedException {
        final List<Certificate> certs = new LinkedList<Certificate>();
        
        for (final byte[] certBytes : signerCerts) {
            final X509Certificate cert =
                    (X509Certificate) CertTools.getCertfromByteArray(certBytes);
            certs.add(cert);
        }
        
        final IWorker worker = workerManagerSession.getWorker(signerId, globalConfigurationSession);
        
        if (worker instanceof IProcessable) {
            try {
                ((IProcessable) worker).importCertificateChain(certs, alias, authenticationCode, Collections.<String, Object>emptyMap(), servicesImpl);
                auditLogCertChainInstalledToToken(adminInfo, EventStatus.SUCCESS, signerId, alias, new String(CertTools.getPEMFromCerts(certs)), null);
            } catch (NoSuchAliasException ex) {
                auditLogCertChainInstalledToToken(adminInfo, EventStatus.FAILURE, signerId, alias, new String(CertTools.getPEMFromCerts(certs)), ex.getMessage());
                throw new CryptoTokenOfflineException("No such alias: " + ex.getLocalizedMessage());
            } catch (InvalidAlgorithmParameterException ex) {
                auditLogCertChainInstalledToToken(adminInfo, EventStatus.FAILURE, signerId, alias, new String(CertTools.getPEMFromCerts(certs)), ex.getMessage());
                throw new CryptoTokenOfflineException(ex);
            } catch (UnsupportedCryptoTokenParameter ex) {
                auditLogCertChainInstalledToToken(adminInfo, EventStatus.FAILURE, signerId, alias, new String(CertTools.getPEMFromCerts(certs)), ex.getMessage());
                throw new CryptoTokenOfflineException(ex);
            } catch (CryptoTokenOfflineException ex) {
                auditLogCertChainInstalledToToken(adminInfo, EventStatus.FAILURE, signerId, alias, new String(CertTools.getPEMFromCerts(certs)), ex.getMessage());
                throw ex;
            }
        } else {
            auditLogCertChainInstalledToToken(adminInfo, EventStatus.FAILURE, signerId, alias, new String(CertTools.getPEMFromCerts(certs)), "Import not supported by worker");
            throw new OperationUnsupportedException("Import not supported by worker");
        }
    }

    @Override
    public void importCertificateChain(final int signerId,
                                       final List<byte[]> signerCerts,
                                       final String alias,
                                       final char[] authenticationCode)
            throws CryptoTokenOfflineException, CertificateException,
                   OperationUnsupportedException {
        importCertificateChain(new AdminInfo("CLI user", null, null), signerId,
                signerCerts, alias, authenticationCode);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#genFreeWorkerId()
     */
    @Override
    public int genFreeWorkerId() {
        Collection<Integer> ids = getWorkers(
                GlobalConfiguration.WORKERTYPE_ALL);
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
     * @see org.signserver.ejb.interfaces.IWorkerSession#findArchiveDataFromArchiveId(int, java.lang.String)
     */
    @Override
    public List<ArchiveDataVO> findArchiveDataFromArchiveId(int signerId,
            String archiveId) {
        final LinkedList<ArchiveDataVO> result = new LinkedList<ArchiveDataVO>();
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
     * @see org.signserver.ejb.interfaces.IWorkerSession#findArchiveDatasFromRequestIP(int, java.lang.String)
     */
    @Override
    public List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerId,
            String requestIP) {
        List<ArchiveDataVO> retval = new LinkedList<ArchiveDataVO>();

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
     * @see org.signserver.ejb.interfaces.IWorkerSession#findArchiveDatasFromRequestCertificate(int, java.math.BigInteger, java.lang.String)
     */
    @Override
    public List<ArchiveDataVO> findArchiveDatasFromRequestCertificate(
            int signerId, BigInteger requestCertSerialnumber,
            String requestCertIssuerDN) {
        ArrayList<ArchiveDataVO> retval = new ArrayList<ArchiveDataVO>();

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
        return workerConfigService.getWorkerProperties(workerId);
    }

    private String generateTransactionID() {
        return UUID.randomUUID().toString();
    }
    
    /**
     * @see org.signserver.ejb.interfaces.IWorkerSession#getWorkers(int)
     */
    @Override
    public List<Integer> getWorkers(int workerType) {
        return workerManagerSession.getWorkers(workerType, globalConfigurationSession);
    }
    
    private void auditLog(final AdminInfo adminInfo, SignServerEventTypes eventType, SignServerModuleTypes module,
    		final String workerId) {
        auditLog(adminInfo, eventType, EventStatus.SUCCESS, module, workerId, Collections.<String, Object>emptyMap());
    }
    
    private void auditLog(final AdminInfo adminInfo, SignServerEventTypes eventType, EventStatus outcome, SignServerModuleTypes module, final String workerId, Map<String, Object> additionalDetails) {
        try {
        	final String serialNo =
        			adminInfo.getCertSerialNumber() == null ? null : adminInfo.getCertSerialNumber().toString(16);
            logSession.log(eventType, outcome, module, SignServerServiceTypes.SIGNSERVER,
                    adminInfo.getSubjectDN(), adminInfo.getIssuerDN(), serialNo, workerId, additionalDetails);                               

        } catch (AuditRecordStorageException ex) {
            LOG.error("Audit log failure", ex);
            throw new EJBException("Audit log failure", ex);
        }
    }
    
    private void setWorkerConfig(final AdminInfo adminInfo, final int workerId, final WorkerConfig config,
    		final String additionalLogKey, final String additionalLogValue) {
        final WorkerConfig oldConfig = workerConfigService.getWorkerProperties(workerId);       
        Map<String, Object> configChanges = WorkerConfig.propertyDiff(oldConfig, config);
        
        if (additionalLogKey != null) {
        	configChanges.put(additionalLogKey, additionalLogValue);
        }
        
        auditLog(adminInfo, SignServerEventTypes.SET_WORKER_CONFIG, EventStatus.SUCCESS, SignServerModuleTypes.WORKER_CONFIG,
        		String.valueOf(workerId), configChanges);
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

    private void initKeyUsageCounter(final IWorker worker,
                                     final ProcessRequest request,
                                     final RequestContext context) {
        // Try to insert a key usage counter entry for this worker's public
        // key
        // Get worker instance
        if (worker instanceof BaseProcessable) {
            try {
                final Certificate cert = ((BaseProcessable)worker)
                        .getSigningCertificate(request, context);
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
    public TokenSearchResults searchTokenEntries(final int workerId, int startIndex, int max, final QueryCriteria qc, final boolean includeData, final Map<String, Object> params) throws
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
    public TokenSearchResults searchTokenEntries(final AdminInfo adminInfo, final int workerId, int startIndex, int max, final QueryCriteria qc, final boolean includeData, final Map<String, Object> params) throws
            InvalidWorkerIdException,
            AuthorizationDeniedException,
            CryptoTokenOfflineException,
            QueryException,
            InvalidAlgorithmParameterException,
            UnsupportedCryptoTokenParameter,
            OperationUnsupportedException {
        final IWorker worker = workerManagerSession.getWorker(workerId, globalConfigurationSession);
        if (worker instanceof IProcessable) {
            return ((IProcessable) worker).searchTokenEntries(startIndex, max, qc, includeData, params, servicesImpl);
        } else {
            throw new OperationUnsupportedException("Operation not supported by worker");
        }
    }
}
