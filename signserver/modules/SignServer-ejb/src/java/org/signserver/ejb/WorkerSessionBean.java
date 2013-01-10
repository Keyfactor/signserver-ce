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
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;

import org.ejbca.util.CertTools;
import org.signserver.common.*;
import org.signserver.common.KeyTestResult;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IServiceTimerSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.ejb.worker.impl.IWorkerManagerSessionLocal;
import org.signserver.server.*;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.ArchiveException;
import org.signserver.server.archive.Archiver;
import org.signserver.server.archive.olddbarchiver.entities.ArchiveDataBean;
import org.signserver.server.archive.olddbarchiver.entities.ArchiveDataService;
import org.signserver.server.config.entities.FileBasedWorkerConfigDataService;
import org.signserver.server.config.entities.IWorkerConfigDataService;
import org.signserver.server.config.entities.WorkerConfigDataService;
import org.signserver.server.entities.FileBasedKeyUsageCounterDataService;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.entities.KeyUsageCounter;
import org.signserver.server.entities.KeyUsageCounterDataService;
import org.signserver.server.log.*;
import org.signserver.server.nodb.FileBasedDatabaseManager;
import org.signserver.server.statistics.Event;
import org.signserver.server.statistics.StatisticsManager;

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

    EntityManager em;
    

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
    }

    /**
     * @see org.signserver.ejb.interfaces.IWorkerSession#process(int, org.signserver.common.ProcessRequest, org.signserver.common.RequestContext)
     */
    @Override
    public ProcessResponse process(final int workerId,
            final ProcessRequest request, final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(">process: " + workerId);
        }

        // Start time
        final long startTime = System.currentTimeMillis();

        // Map of log entries
        final LogMap logMap = LogMap.getInstance(requestContext);
                
        // Get transaction ID or create new if not created yet
        final String transactionID;
        if (requestContext.get(RequestContext.TRANSACTION_ID) == null) {
            transactionID = generateTransactionID();
        } else {
            transactionID = (String) requestContext.get(
                    RequestContext.TRANSACTION_ID);
        }

        // Store values for request context and logging
        requestContext.put(RequestContext.WORKER_ID, Integer.valueOf(workerId));
        requestContext.put(RequestContext.TRANSACTION_ID, transactionID);
        logMap.put(IWorkerLogger.LOG_TIME, String.valueOf(startTime));
        logMap.put(IWorkerLogger.LOG_ID, transactionID);
        logMap.put(IWorkerLogger.LOG_WORKER_ID, String.valueOf(workerId));
        logMap.put(IWorkerLogger.LOG_CLIENT_IP,
                (String) requestContext.get(RequestContext.REMOTE_IP));

        // Get worker instance
        final IWorker worker = workerManagerSession.getWorker(workerId, globalConfigurationSession);

        if (worker == null) {
            throw new NoSuchWorkerException(String.valueOf(workerId));
        }
        final WorkerConfig awc = worker.getConfig();

        // Get worker log instance
        final IWorkerLogger workerLogger = workerManagerSession.getWorkerLogger(workerId, awc);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Worker[" + workerId + "]: " + "WorkerLogger: "
                    + workerLogger);
        }

        try {
            // Get processable
            if (!(worker instanceof IProcessable)) {
                final IllegalRequestException ex = new IllegalRequestException(
                        "Worker exists but isn't a processable: " + workerId);
                // auditLog(startTime, workerId, false, requestContext, ex);
                logException(ex, logMap, workerLogger);
                throw ex;
            }
            final IProcessable processable = (IProcessable) worker;

            // Check authorization
            logMap.put(IWorkerLogger.LOG_WORKER_AUTHTYPE,
                    processable.getAuthenticationType());
            try {
                workerManagerSession.getAuthenticator(workerId,
                            processable.getAuthenticationType(),
                            awc).isAuthorized(request, requestContext);
                logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED,
                        String.valueOf(true));
            } catch (AuthorizationRequiredException ex) {
                throw ex;
            } catch (AccessDeniedException ex) {
                throw ex;
            } catch (IllegalRequestException ex) {
                final IllegalRequestException exception =
                        new IllegalRequestException("Authorization failed: "
                        + ex.getMessage(), ex);
                logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED,
                        String.valueOf(false));
                logException(ex, logMap, workerLogger);
                throw exception;
            } catch (SignServerException ex) {
                final SignServerException exception =
                        new SignServerException("Authorization failed: "
                        + ex.getMessage(), ex);
                logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED,
                        String.valueOf(false));
                logException(ex, logMap, workerLogger);
                throw exception;
            }

            // Log client certificate (if any)
            final Certificate clientCertificate = (Certificate)
                    requestContext.get(RequestContext.CLIENT_CERTIFICATE);
            if (clientCertificate instanceof X509Certificate) {
                final X509Certificate cert = (X509Certificate) clientCertificate;
                logMap.put(IWorkerLogger.LOG_CLIENT_CERT_SUBJECTDN,
                        cert.getSubjectDN().getName());
                logMap.put(IWorkerLogger.LOG_CLIENT_CERT_ISSUERDN,
                        cert.getIssuerDN().getName());
                logMap.put(IWorkerLogger.LOG_CLIENT_CERT_SERIALNUMBER,
                        cert.getSerialNumber().toString(16));
            }

            // Check activation
            if (awc.getProperties().getProperty(SignServerConstants.DISABLED,
                    "FALSE").equalsIgnoreCase("TRUE")) {
                final CryptoTokenOfflineException exception =
                        new CryptoTokenOfflineException("Error Signer : "
                        + workerId
                        + " is disabled and cannot perform any signature operations");
                logException(exception, logMap, workerLogger);
                throw exception;
            }

            // Check signer certificate
            final boolean counterDisabled = awc.getProperties().getProperty(SignServerConstants.DISABLEKEYUSAGECOUNTER, "FALSE").equalsIgnoreCase("TRUE");
            final long keyUsageLimit;
            try {
                keyUsageLimit = Long.valueOf(awc.getProperty(SignServerConstants.KEYUSAGELIMIT, "-1"));
            } catch (NumberFormatException ex) {
                final SignServerException exception = new SignServerException("Incorrect value in worker property " + SignServerConstants.KEYUSAGELIMIT, ex);
                logException(exception, logMap, workerLogger);
                throw exception;
            }
            final boolean keyUsageLimitSpecified = keyUsageLimit != -1;
            if (counterDisabled && keyUsageLimitSpecified) {
                LOG.error("Worker]" + workerId + "]: Configuration error: " +  SignServerConstants.DISABLEKEYUSAGECOUNTER + "=TRUE but " + SignServerConstants.KEYUSAGELIMIT + " is also configured. Key usage counter will still be used.");
            }
            try {
                // Check if the signer has a signer certificate and if that
                // certificate have ok validity and private key usage periods.
                checkSignerValidity(workerId, awc, logMap);

                // Check key usage limit (preliminary check only)
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Key usage counter disabled: " + counterDisabled);
                }
                if (!counterDisabled || keyUsageLimitSpecified) {
                    checkSignerKeyUsageCounter(processable, workerId, awc, em,
                            false);
                }
            } catch (CryptoTokenOfflineException ex) {
                final CryptoTokenOfflineException exception =
                        new CryptoTokenOfflineException(ex);
                logException(exception, logMap, workerLogger);
                throw exception;
            }

            // Statistics: start event
            final Event event = StatisticsManager.startEvent(workerId, awc, em);
            requestContext.put(RequestContext.STATISTICS_EVENT, event);

            // Process the request
            final ProcessResponse res;
            try {
                res = processable.processData(request, requestContext);
            } catch (AuthorizationRequiredException ex) {
              throw ex; // This can happen in dispatching workers
            } catch (SignServerException e) {
                final SignServerException exception = new SignServerException(
                        "SignServerException calling signer with id " + workerId
                        + " : " + e.getMessage(), e);
                LOG.error(exception.getMessage(), exception);
                logException(exception, logMap, workerLogger);
                throw exception;
            } catch (IllegalRequestException ex) {
                final IllegalRequestException exception =
                        new IllegalRequestException(ex.getMessage());
				if (LOG.isInfoEnabled()) {
					LOG.info("Illegal request calling signer with id " + workerId
                        + " : " + ex.getMessage());
				}
				logException(exception, logMap, workerLogger);
                throw exception;
            } catch (CryptoTokenOfflineException ex) {
                final CryptoTokenOfflineException exception =
                        new CryptoTokenOfflineException(ex);
                logException(exception, logMap, workerLogger);
                throw exception;
            }

            // Charge the client if the request was successfull
            if (Boolean.TRUE.equals(requestContext.get(
                    RequestContext.WORKER_FULFILLED_REQUEST))) {

                // Billing time
                boolean purchased = false;
                try {
                    IClientCredential credential =
                            (IClientCredential) requestContext.get(
                                        RequestContext.CLIENT_CREDENTIAL);

                    purchased = workerManagerSession.getAccounter(workerId,
                                    awc).purchase(credential, request, res,
                                            requestContext);

                    logMap.put(IWorkerLogger.LOG_PURCHASED, "true");
                } catch (AccounterException ex) {
                    logMap.put(IWorkerLogger.LOG_PURCHASED, "false");
                    final SignServerException exception =
                            new SignServerException("Accounter failed: "
                            + ex.getMessage(), ex);
                    logException(ex, logMap, workerLogger);
                    throw exception;
                }
                if (!purchased) {
                    final String error = "Purchase not granted";
                    logMap.put(IWorkerLogger.LOG_EXCEPTION, error);
                    logMap.put(IWorkerLogger.LOG_PROCESS_SUCCESS, String.valueOf(false));
                    workerLogger.log(logMap);
                    throw new NotGrantedException(error);
                }
            } else {
                logMap.put(IWorkerLogger.LOG_PURCHASED, "false");
            }

            // Archiving
            if (res instanceof IArchivableProcessResponse) {
                final IArchivableProcessResponse arres =
                        (IArchivableProcessResponse) res;
                final Collection<? extends Archivable> archivables = arres.getArchivables();
                if (archivables != null) {
                    // Archive all Archivables using all ArchiverS
                    final List<Archiver> archivers = workerManagerSession.getArchivers(workerId, awc);
                    if (archivers != null) {
                        try {
                            for (Archiver archiver : archivers) {
                                for (Archivable archivable : archivables) {

                                    final boolean archived = archiver.archive(
                                            archivable, requestContext);

                                    if (LOG.isDebugEnabled()) {
                                        final StringBuilder buff = new StringBuilder();
                                        buff.append("Archiver ");
                                        buff.append(archiver);
                                        buff.append(" archived request: ");
                                        buff.append(archived);
                                        LOG.debug(buff.toString());
                                    }
                                }
                            }
                        } catch (ArchiveException ex) {
                            LOG.error("Archiving failed", ex);
                            throw new SignServerException(
                                    "Archiving failed. See server LOG.");
                        }
                    }
                }
            }

            // Statistics: end event
            StatisticsManager.endEvent(workerId, awc, em, event);

            // Check key usage limit
            if (!counterDisabled || keyUsageLimitSpecified) {
                checkSignerKeyUsageCounter(processable, workerId, awc, em, true);
            }

            // Output successfully
            if (res instanceof ISignResponse) {
                LOG.info("Worker " + workerId + " Processed request "
                        + ((ISignResponse) res).getRequestID()
                        + " successfully");
            } else {
                LOG.info("Worker " + workerId
                        + " Processed request successfully");
            }

            // Old log entries (SignServer 3.1) added for backward compatibility
            // Log: REQUESTID
            if (res instanceof ISignResponse) {
                logMap.put("REQUESTID",
                        String.valueOf(((ISignResponse) res).getRequestID()));
            }

            // Log
            String logVal = logMap.get(IWorkerLogger.LOG_PROCESS_SUCCESS);
            // log process status true if not already set by the worker...
            if (logVal == null) {
            	logMap.put(IWorkerLogger.LOG_PROCESS_SUCCESS, String.valueOf(true));
            	workerLogger.log(logMap);
            }
            
            // TODO: make audit logging using CESeCore here configurable
            /*
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", "start services startup msg");
            try {
                
                logSession.log(SignServerEventTypes.PROCESS, EventStatus.SUCCESS, SignServerModuleTypes.SERVICE, SignServerServiceTypes.SIGNSERVER,
                        "WorkerSessionBean.process", null, null, null, null);                               

                LOG.info("After logging");
            } catch (AuditRecordStorageException ex) {
                LOG.error("Logging", ex);
            }*/

            LOG.debug("<process");
            return res;

        } catch (WorkerLoggerException ex) {
            final SignServerException exception =
                    new SignServerException("Logging failed", ex);
            LOG.error(exception.getMessage(), exception);
            throw exception;
        }
    }

    private void logException(Exception ex, LogMap logMap,
    		IWorkerLogger workerLogger) throws WorkerLoggerException {
    	logMap.put(IWorkerLogger.LOG_EXCEPTION, ex.getMessage());
    	logMap.put(IWorkerLogger.LOG_PROCESS_SUCCESS, String.valueOf(false));
    	workerLogger.log(logMap);
    }
    
    /**
     * Verify the certificate validity times, the PrivateKeyUsagePeriod and
     * that the minremaining validity is ok.
     *
     * @param workerId
     * @param awc
     * @throws CryptoTokenOfflineException
     */
    private void checkSignerValidity(final int workerId,
            final WorkerConfig awc, final LogMap logMap)
            throws CryptoTokenOfflineException {

        // If the signer have a certificate, check that it is usable
        final Certificate signerCert = getSignerCertificate(workerId);
        if (signerCert instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate) signerCert;

            // Log client certificate
            logMap.put(IWorkerLogger.LOG_SIGNER_CERT_SUBJECTDN,
                    cert.getSubjectDN().getName());
            logMap.put(IWorkerLogger.LOG_SIGNER_CERT_ISSUERDN,
                    cert.getIssuerDN().getName());
            logMap.put(IWorkerLogger.LOG_SIGNER_CERT_SERIALNUMBER,
                    cert.getSerialNumber().toString(16));

            ValidityTimeUtils.checkSignerValidity(workerId, awc, cert);
        } else { // if (cert != null)
            if (LOG.isDebugEnabled()) {
                LOG.debug("Worker does not have a signing certificate. Worker: "
                        + workerId);
            }
        }
        
    } // checkCertificateValidity

    /**
     * Gets the last date the specified worker can do signings.
     * @param workerId Id of worker to check.
     * @return The last date or null if no last date (=unlimited).
     * @throws CryptoTokenOfflineException In case the cryptotoken is offline
     * for some reason.
     */
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

    /**
     * Checks that if this worker has a certificate (ie the worker is a Signer)
     * the counter of the usages of the key has not reached the configured
     * limit.
     * @param workerId
     * @param awc
     * @param em
     * @throws CryptoTokenOfflineException
     */
    private void checkSignerKeyUsageCounter(final IProcessable worker,
            final int workerId, final WorkerConfig awc, EntityManager em,
            final boolean increment)
        throws CryptoTokenOfflineException {
        
        // If the signer have a certificate, check that the usage of the key
        // has not reached the limit
        Certificate cert = null;

        if (worker instanceof BaseProcessable) {
            cert = ((BaseProcessable) worker).getSigningCertificate();
        } else {
            // The following will not work for keystores where the SIGNSERCERT
            // property is not set
            cert = (new ProcessableConfig(awc)).getSignerCertificate();
        }

        if (cert != null) {
            final long keyUsageLimit
                    = Long.valueOf(awc.getProperty(SignServerConstants.KEYUSAGELIMIT, "-1"));

            final String keyHash
                    = KeyUsageCounterHash.create(cert.getPublicKey());

            if (LOG.isDebugEnabled()) {
                LOG.debug("Worker[" + workerId +"]: "
                        + "Key usage limit: " + keyUsageLimit);
                LOG.debug("Worker[" + workerId +"]: "
                        + "Key hash: " + keyHash);
            }

            if (increment) {
                if (!keyUsageCounterDataService.incrementIfWithinLimit(keyHash, keyUsageLimit)) {
                        final String message
                                = "Key usage limit exceeded or not initialized for worker "
                                + workerId;
                        LOG.debug(message);
                        throw new CryptoTokenOfflineException(message);
                    }
            } else {
                // Just check the value without updating
                if (keyUsageLimit > -1) {
                    if (!keyUsageCounterDataService.isWithinLimit(keyHash, keyUsageLimit)) {
                        final String message
                            = "Key usage limit exceeded or not initialized for worker "
                            + workerId;
                        LOG.debug(message);
                        throw new CryptoTokenOfflineException(message);
                    }
                }
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Worker[" + workerId + "]: "
                    + "No certificate so not checking signing key usage counter");
            }
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
        return worker.getStatus(errorsAtEjbLevel);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#getWorkerId(java.lang.String)
     */
    public int getWorkerId(String signerName) {
        return workerManagerSession.getIdFromName(signerName, globalConfigurationSession);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#reloadConfiguration(int)
     */
    public void reloadConfiguration(int workerId) {
        if (workerId == 0) {
            globalConfigurationSession.reload();
        } else {
            workerManagerSession.reloadWorker(workerId, globalConfigurationSession);

            // Try to insert a key usage counter entry for this worker's public
            // key
            // Get worker instance
            final IWorker worker = workerManagerSession.getWorker(workerId, globalConfigurationSession);
            if (worker instanceof BaseProcessable) {
                try {
                    final Certificate cert = ((BaseProcessable)worker)
                            .getSigningCertificate();
                    if (cert != null) {
                        final String keyHash = KeyUsageCounterHash
                                .create(cert.getPublicKey());

                        KeyUsageCounter counter
                                = keyUsageCounterDataService.getCounter(keyHash);

                        if (counter == null) {
                            keyUsageCounterDataService.create(keyHash);
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Worker[" + workerId + "]: "
                                        + "new key usage counter initialized");
                            }
                        } else {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Worker[" + workerId + "]: "
                                        + "key usage counter: " + counter.getCounter());
                            }
                        }
                    }
                } catch (CryptoTokenOfflineException ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Worker[ " + workerId + "]: "
                            + "Crypto token offline trying to create key usage counter");
                    }
                }
            }
        }

        if (workerId == 0 || getWorkers(
                GlobalConfiguration.WORKERTYPE_SERVICES).contains(new Integer(
                workerId))) {
            serviceTimerSession.unload(workerId);
            serviceTimerSession.load(workerId);
        }

        StatisticsManager.flush(workerId);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#activateSigner(int, java.lang.String)
     */
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
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#deactivateSigner(int)
     */
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

    /**
     * @see IWorkerSession#generateSignerKey(int, java.lang.String,
     *  java.lang.String, java.lang.String, char[])
     */
    @Override
    public String generateSignerKey(final int signerId, String keyAlgorithm,
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

        signer.generateKey(keyAlgorithm, keySpec, alias,
                authCode);
        
        final HashMap<String, Object> auditMap = new HashMap<String, Object>();
        auditMap.put("KEYALG", keyAlgorithm);
        auditMap.put("KEYSPEC", keySpec);
        auditMap.put("KEYALIAS", alias);
        auditLog(SignServerEventTypes.KEYGEN, SignServerModuleTypes.KEY_MANAGEMENT, String.valueOf(signerId), auditMap);
        return alias;
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

    /**
     * @see IWorkerSession#testKey(int, java.lang.String, char[])
     */
    @Override
    public Collection<KeyTestResult> testKey(final int signerId, String alias,
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
        
        final Collection<KeyTestResult> result = signer.testKey(alias, authCode);
        final HashMap<String, Object> auditMap = new HashMap<String, Object>();
        auditMap.put("KEYALIAS", alias);
        auditMap.put("TESTRESULTS", createResultsReport(result));
        auditLog(SignServerEventTypes.KEYTEST, SignServerModuleTypes.KEY_MANAGEMENT, String.valueOf(signerId), auditMap);
        
        return result;
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.IWorkerSession#getCurrentSignerConfig(int)
     */
    public WorkerConfig getCurrentWorkerConfig(int signerId) {
        return getWorkerConfig(signerId);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#setWorkerProperty(int, java.lang.String, java.lang.String)
     */
    @Override
    public void setWorkerProperty(int workerId, String key, String value) {
        WorkerConfig config = getWorkerConfig(workerId);
        config.setProperty(key.toUpperCase(), value);
        setWorkerConfig(workerId, config, null, null);
        auditLogWorkerPropertyChange(workerId, key, value);
    }
    
    private void auditLogCertInstalled(final int workerId, final String value, final String scope, final String node) {
        final HashMap<String, Object> auditMap = new HashMap<String, Object>();
        auditMap.put("CERTIFICATE", value);
        auditMap.put("SCOPE", scope);
        if ("NODE".equalsIgnoreCase(scope)) {
            auditMap.put("NODE", node);
        }
        auditLog(SignServerEventTypes.CERTINSTALLED, SignServerModuleTypes.WORKER_CONFIG, String.valueOf(workerId), auditMap);
    }
    
    private void auditLogCertChainInstalled(final int workerId, final String value, final String scope, final String node) {
        final HashMap<String, Object> auditMap = new HashMap<String, Object>();
        auditMap.put("CERTIFICATECHAIN", value);
        auditMap.put("SCOPE", scope);
        if ("NODE".equalsIgnoreCase(scope)) {
            auditMap.put("NODE", node);
        }
        auditLog(SignServerEventTypes.CERTCHAININSTALLED, SignServerModuleTypes.WORKER_CONFIG, String.valueOf(workerId), auditMap);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#removeWorkerProperty(int, java.lang.String)
     */
    @Override
    public boolean removeWorkerProperty(int workerId, String key) {
        final boolean result;
        WorkerConfig config = getWorkerConfig(workerId);

        result = config.removeProperty(key.toUpperCase());
        if (config.getProperties().size() == 0) {
            workerConfigService.removeWorkerConfig(workerId);
            LOG.debug("WorkerConfig is empty and therefore removed.");
            auditLog(SignServerEventTypes.SET_WORKER_CONFIG, SignServerModuleTypes.WORKER_CONFIG, String.valueOf(workerId));
        } else {
            setWorkerConfig(workerId, config, null, null);
        }
        auditLogWorkerPropertyChange(workerId, key, "");
        return result;
    }
    
    private void auditLogWorkerPropertyChange(final int workerId, final String key, final String value) {
        if ("DEFAULTKEY".equalsIgnoreCase(key)) {
            final HashMap<String, Object> auditMap = new HashMap<String, Object>();
            auditMap.put("KEYALIAS", value);
            auditMap.put("SCOPE", "GLOBAL");
            auditLog(SignServerEventTypes.KEYSELECTED, SignServerModuleTypes.WORKER_CONFIG, String.valueOf(workerId), auditMap);
        } else if (key != null && key.lastIndexOf(".") != -1 && key.substring(key.lastIndexOf(".")).equalsIgnoreCase(".DEFAULTKEY")) {
            final HashMap<String, Object> auditMap = new HashMap<String, Object>();
            auditMap.put("KEYALIAS", value);
            auditMap.put("SCOPE", "NODE");
            auditMap.put("NODE", key.substring(0, key.lastIndexOf(".")));
            auditLog(SignServerEventTypes.KEYSELECTED, SignServerModuleTypes.WORKER_CONFIG, String.valueOf(workerId), auditMap);
        } else if (ProcessableConfig.SIGNERCERT.equalsIgnoreCase(key)) {
            auditLogCertInstalled(workerId, value, "GLOBAL", null);
        } else if (key != null && key.lastIndexOf(".") != -1 && key.substring(key.lastIndexOf(".")).equalsIgnoreCase("." + ProcessableConfig.SIGNERCERT)) {
            auditLogCertInstalled(workerId, value, "NODE", key.substring(0, key.lastIndexOf(".")));
        } else if (ProcessableConfig.SIGNERCERTCHAIN.equalsIgnoreCase(key)) {
            auditLogCertChainInstalled(workerId, value, "GLOBAL", null);
        } else if (key != null && key.lastIndexOf(".") != -1 && key.substring(key.lastIndexOf(".")).equalsIgnoreCase("." + ProcessableConfig.SIGNERCERTCHAIN)) {
            auditLogCertChainInstalled(workerId, value, "NODE", key.substring(0, key.lastIndexOf(".")));
        }
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#getAuthorizedClients(int)
     */
    public Collection<AuthorizedClient> getAuthorizedClients(int signerId) {
        return new ProcessableConfig(getWorkerConfig(signerId)).
                getAuthorizedClients();
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#addAuthorizedClient(int, org.signserver.common.AuthorizedClient)
     */
    public void addAuthorizedClient(int signerId, AuthorizedClient authClient) {
        WorkerConfig config = getWorkerConfig(signerId);
        (new ProcessableConfig(config)).addAuthorizedClient(authClient);
        setWorkerConfig(signerId, config, "added:authorized_client",
        		"SN: " + authClient.getCertSN() + ", issuer DN: " + authClient.getIssuerDN());
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#removeAuthorizedClient(int, org.signserver.common.AuthorizedClient)
     */
    public boolean removeAuthorizedClient(int signerId,
            AuthorizedClient authClient) {
        boolean result = false;
        WorkerConfig config = getWorkerConfig(signerId);


        result = (new ProcessableConfig(config)).removeAuthorizedClient(
                authClient);
        setWorkerConfig(signerId, config, "removed:authorized_client",
        		"SN: " + authClient.getCertSN() + ", issuer DN: " + authClient.getIssuerDN());
        return result;
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#getCertificateRequest(int, org.signserver.common.ISignerCertReqInfo)
     */
    public ICertReqData getCertificateRequest(final int signerId,
            final ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
        return getCertificateRequest(signerId, certReqInfo, 
                explicitEccParameters, true);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#getCertificateRequest(int, org.signserver.common.ISignerCertReqInfo)
     */
    @Override
    public ICertReqData getCertificateRequest(int signerId,
            ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters,
            final boolean defaultKey) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
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

        ICertReqData ret = processable.genCertificateRequest(certReqInfo,
                explicitEccParameters, defaultKey);
        
        
        final HashMap<String, Object> auditMap = new HashMap<String, Object>();
        
        final String csr;
        if (ret instanceof Base64SignerCertReqData) {
            csr = new String(((Base64SignerCertReqData) ret).getBase64CertReq());
        } else {
            csr = ret.toString();
        }
        
        auditMap.put("CSR", csr);
        auditLog(SignServerEventTypes.GENCSR, SignServerModuleTypes.KEY_MANAGEMENT, String.valueOf(signerId), auditMap);
        
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getCertificateRequest: signerId=" + signerId);
        }
        return ret;
    }

    /**
     * @see org.signserver.ejb.interfaces.IWorkerSession#getSignerCertificate(int)
     */
    public Certificate getSignerCertificate(final int signerId) throws CryptoTokenOfflineException {
        Certificate ret = null;
        final IWorker worker = workerManagerSession.getWorker(signerId, globalConfigurationSession);
        if (worker instanceof BaseProcessable) {
            ret = ((BaseProcessable) worker).getSigningCertificate();
        }
        return ret;
    }

    /**
     * @see org.signserver.ejb.interfaces.IWorkerSession#getSigningCertificateChain(int)
     */
    @Override
    public List<Certificate> getSignerCertificateChain(final int signerId)
            throws CryptoTokenOfflineException {
        List<Certificate> ret = null;
        IWorker worker = workerManagerSession.getWorker(signerId, globalConfigurationSession);
        if (worker instanceof BaseProcessable) {
            ret = ((BaseProcessable) worker).getSigningCertificateChain();
        }
        return ret;
    }
    
    /**
     * @see org.signserver.ejb.interfaces.IWorkerSession#getSignerCertificateBytes(int) 
     */
    @Override
    public byte[] getSignerCertificateBytes(final int signerId) 
            throws CryptoTokenOfflineException {
        try {
            final Certificate cert = getSignerCertificate(signerId);
            return cert == null ? null : cert.getEncoded();
        } catch (CertificateEncodingException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
    }

    /**
     * @see org.signserver.ejb.interfaces.IWorkerSession#getSignerCertificateChain(int)
     */
    @Override
    public List<byte[]> getSignerCertificateChainBytes(final int signerId)
            throws CryptoTokenOfflineException {
        final List<Certificate> certs = getSignerCertificateChain(signerId);
        final List<byte[]> res = new LinkedList<byte[]>();
        try {
            for (Certificate cert : certs) {
                res.add(cert.getEncoded());
            }
        } catch (CertificateEncodingException ex) {
            throw new CryptoTokenOfflineException(ex);
        }
        return res;
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#destroyKey(int, int)
     */
    public boolean destroyKey(int signerId, int purpose) throws
            InvalidWorkerIdException {
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

        return signer.destroyKey(purpose);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#uploadSignerCertificate(int, java.security.cert.X509Certificate, java.lang.String)
     */
    @Override
    public void uploadSignerCertificate(int signerId, byte[] signerCert,
            String scope) throws CertificateException {
        WorkerConfig config = getWorkerConfig(signerId);

        final Certificate cert  = CertTools.getCertfromByteArray(signerCert);
        ( new ProcessableConfig(config)).setSignerCertificate((X509Certificate)cert,scope);
        setWorkerConfig(signerId, config, null, null);
        final boolean scopeGlobal = GlobalConfiguration.SCOPE_GLOBAL.equalsIgnoreCase(scope);
        auditLogCertInstalled(signerId, new String (CertTools.getPEMFromCerts(Arrays.asList(cert))), scopeGlobal ? "GLOBAL" : "NODE", scopeGlobal ? null : WorkerConfig.getNodeId());
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#uploadSignerCertificateChain(int, java.util.Collection, java.lang.String)
     */
    @Override
    public void uploadSignerCertificateChain(int signerId,
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
        setWorkerConfig(signerId, config, null, null);
        final boolean scopeGlobal = GlobalConfiguration.SCOPE_GLOBAL.equalsIgnoreCase(scope);
        auditLogCertChainInstalled(signerId, new String (CertTools.getPEMFromCerts(certs)), scopeGlobal ? "GLOBAL" : "NODE", scopeGlobal ? null : WorkerConfig.getNodeId());
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#genFreeWorkerId()
     */
    public int genFreeWorkerId() {
        Collection<Integer> ids = getWorkers(
                GlobalConfiguration.WORKERTYPE_ALL);
        int max = 0;
        Iterator<Integer> iter = ids.iterator();
        while (iter.hasNext()) {
            Integer id = iter.next();
            if (id.intValue() > max) {
                max = id.intValue();
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
    
    private void auditLog(SignServerEventTypes eventType, SignServerModuleTypes module, String customId) {
        auditLog(eventType, module, customId, Collections.<String, Object>emptyMap());
    }
    
    private void auditLog(SignServerEventTypes eventType, SignServerModuleTypes module, String customId, Map<String, Object> additionalDetails) {
        try {
            logSession.log(eventType, EventStatus.SUCCESS, module, SignServerServiceTypes.SIGNSERVER,
                    "WorkerSessionBean.auditLog", customId, null, null, additionalDetails);                               

        } catch (AuditRecordStorageException ex) {
            LOG.error("Audit log failure", ex);
            throw new EJBException("Audit log failure", ex);
        }
    }
    
    private void setWorkerConfig(final int workerId, final WorkerConfig config,
    		final String additionalLogKey, final String additionalLogValue) {
        final WorkerConfig oldConfig = workerConfigService.getWorkerProperties(workerId);       
        Map<String, Object> configChanges = WorkerConfig.propertyDiff(oldConfig, config);
        
        if (additionalLogKey != null) {
        	configChanges.put(additionalLogKey, additionalLogValue);
        }
        
        auditLog(SignServerEventTypes.SET_WORKER_CONFIG, SignServerModuleTypes.WORKER_CONFIG, String.valueOf(workerId), configChanges);
        workerConfigService.setWorkerConfig(workerId, config);
    }

    private String createResultsReport(final Collection<KeyTestResult> results) {
        final StringBuilder buff = new StringBuilder();
        for (KeyTestResult result : results) {
            buff.append(result.toString()).append("\n");
        }
        return buff.toString();
    }
    
}
