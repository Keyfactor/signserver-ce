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

import org.signserver.common.WorkerIdentifier;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.signserver.common.AccessDeniedException;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IArchivableProcessResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.NotGrantedException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.DocumentValidationResponse;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureResponse;
import org.signserver.ejb.worker.impl.WorkerManagerSingletonBean;
import org.signserver.ejb.worker.impl.WorkerWithComponents;
import org.signserver.server.AccounterException;
import org.signserver.server.IAuthorizer;
import org.signserver.server.IClientCredential;
import org.signserver.server.IProcessable;
import org.signserver.server.KeyUsageCounterHash;
import org.signserver.server.ValidityTimeUtils;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.ArchiveException;
import org.signserver.server.archive.Archiver;
import org.signserver.server.cryptotokens.CryptoInstances;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.SignServerEventTypes;
import org.signserver.server.log.SignServerModuleTypes;
import org.signserver.server.log.SignServerServiceTypes;
import org.signserver.server.log.WorkerLoggerException;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.ejb.worker.impl.PreloadedWorkerConfig;
import org.signserver.server.IServices;
import org.signserver.server.log.ExceptionLoggable;
import org.signserver.server.log.Loggable;

/**
 * Implements the business logic for the process method.
 *
 * @version $Id$
 */
class WorkerProcessImpl {

    /** Log4j instance for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerProcessImpl.class);

    private final EntityManager em;

    private final IKeyUsageCounterDataService keyUsageCounterDataService;

    private final WorkerManagerSingletonBean workerManagerSession;

    private final SecurityEventsLoggerSessionLocal logSession;

    /**
     * Constructs a new instance of WorkerProcessImpl.
     * @param em The EntityManager (if used)
     * @param keyUsageCounterDataService The key usage counter data service
     * @param workerManagerSession The worker manager session
     * @param logSession The log session
     */
    public WorkerProcessImpl(EntityManager em, IKeyUsageCounterDataService keyUsageCounterDataService, WorkerManagerSingletonBean workerManagerSession, SecurityEventsLoggerSessionLocal logSession) {
        this.em = em;
        this.keyUsageCounterDataService = keyUsageCounterDataService;
        this.workerManagerSession = workerManagerSession;
        this.logSession = logSession;
    }

    

    /**
     * @see WorkerSession#process(int, org.signserver.common.ProcessRequest, org.signserver.common.RequestContext)
     */
    public Response process(WorkerIdentifier wi, Request request, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        return process(new AdminInfo("Client user", null, null), wi, request, requestContext);
    }

    /**
     * @see WorkerSessionLocal#process(org.signserver.server.log.AdminInfo, int, org.signserver.common.ProcessRequest, org.signserver.common.RequestContext)
     */
    public Response process(final AdminInfo adminInfo, final WorkerIdentifier wi,
            final Request request, final RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException {

        if (LOG.isDebugEnabled()) {
            LOG.debug(">process: " + wi);
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
        requestContext.put(RequestContext.TRANSACTION_ID, transactionID);
        requestContext.put(RequestContext.EM, em);
        logMap.put(IWorkerLogger.LOG_TIME, startTime);
        logMap.put(IWorkerLogger.LOG_ID, transactionID);
        logMap.put(IWorkerLogger.LOG_CLIENT_IP,
                   (String) requestContext.get(RequestContext.REMOTE_IP));

        // Get worker instance
        final WorkerWithComponents worker;
        try {
            worker = workerManagerSession.getWorkerWithComponents(wi);
        } catch (NoSuchWorkerException ex) {
            Map<String, Object> details = new LinkedHashMap<>();
            final String serNo = adminInfo.getCertSerialNumber() != null ? adminInfo.getCertSerialNumber().toString(16) : null;

            // produce backwards-compatible log entries here...
            details.put(IWorkerLogger.LOG_EXCEPTION, ex.getMessage());
            details.put(IWorkerLogger.LOG_PROCESS_SUCCESS, String.valueOf(false));
            // duplicate entries that would have gone to the worker log
            details.put(IWorkerLogger.LOG_TIME, String.valueOf(startTime));
            details.put(IWorkerLogger.LOG_ID, transactionID);
            details.put(IWorkerLogger.LOG_CLIENT_IP, (String) requestContext.get(RequestContext.REMOTE_IP));
            logSession.log(SignServerEventTypes.PROCESS, EventStatus.FAILURE, SignServerModuleTypes.WORKER, SignServerServiceTypes.SIGNSERVER,
                    adminInfo.getSubjectDN(), adminInfo.getIssuerDN(), serNo, null, details);
            throw ex;
        }

        // Store ID now that we are sure we have it
        final int workerId = worker.getId();
        requestContext.put(RequestContext.WORKER_ID, workerId);
        logMap.put(IWorkerLogger.LOG_WORKER_ID, workerId);

        final WorkerConfig awc = worker.getWorker().getConfig();
        final PreloadedWorkerConfig pwc = worker.getPreloadedConfig();

        // Log the worker name
        logMap.put(IWorkerLogger.LOG_WORKER_NAME, pwc.getName());

        // Get worker log instance
        final IWorkerLogger workerLogger = worker.getWorkerLogger();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Worker[" + wi + "]: " + "WorkerLogger: "
                    + workerLogger);
        }
        
        // Put worker identifier
        final WorkerIdentifier wiBoth = new WorkerIdentifier(workerId, pwc.getName());
        requestContext.put(RequestContext.WORKER_IDENTIFIER, wiBoth);
        if (requestContext.get(RequestContext.ORIGINAL_WORKER_IDENTIFIER) == null) {
            requestContext.put(RequestContext.ORIGINAL_WORKER_IDENTIFIER, wiBoth);
        }

        try {
            // Get processable
            if (!(worker.getWorker() instanceof IProcessable)) {
                final IllegalRequestException ex = new IllegalRequestException(
                        "Worker exists but isn't a processable: " + wi);
                // auditLog(startTime, workerId, false, requestContext, ex);
                logException(adminInfo, ex, logMap, workerLogger, requestContext);
                throw ex;
            }
            final IProcessable processable = (IProcessable) worker.getWorker();

            // Authorizer
            handleAuthorization(processable, worker, request, logMap, adminInfo, workerLogger, requestContext);

            // Check activation
            if (pwc.isDisabled()) {
                final CryptoTokenOfflineException exception =
                        new CryptoTokenOfflineException("Error Signer : "
                        + wi
                        + " is disabled and cannot perform any signature operations");
                logException(adminInfo, exception, logMap, workerLogger, requestContext);
                throw exception;
            }

            // Check for errors at EJB level
            if (worker.hasCreateErrors()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Worker " + wi + " has create errors: " + worker.getCreateErrors());
                }
                final SignServerException exception = new SignServerException("Worker is misconfigured");
                LOG.error(exception.getMessage(), exception);
                logException(adminInfo, exception, logMap, workerLogger, requestContext);
                throw exception;
            }

            // Process the request
            final Response res = handleProcessing(processable, workerId, request, requestContext, logMap, workerLogger, adminInfo);

            // Check signer certificate            
            Certificate signerCertificate = null;
            if (res instanceof SignatureResponse) {
                signerCertificate = ((SignatureResponse) res).getSignerCertificate();
            }
            handleSignerCertificate(signerCertificate, workerId, logMap, pwc, requestContext, workerLogger, adminInfo);

            // Charge the client if the request was successfull
            handleAccounting(worker, requestContext, logMap, request, res, workerLogger, adminInfo);

            // Archiving
            handleArchiving(res, worker, requestContext);

            // Check key usage limit
            if (!pwc.isDisableKeyUsageCounter() || pwc.isKeyUsageLimitSpecified()) {
                checkSignerKeyUsageCounter(signerCertificate, workerId, pwc.getKeyUsageLimit(), em, true, requestContext.getServices());
            }

            // Output successfully
            if (LOG.isDebugEnabled()) {
                if (res instanceof SignatureResponse) {
                    LOG.debug("Worker " + wi + " Processed request "
                            + ((SignatureResponse) res).getRequestID()
                            + " successfully");
                } else if (res instanceof DocumentValidationResponse) {
                    LOG.debug("Worker " + wi + " Processed request "
                            + ((DocumentValidationResponse) res).getRequestID()
                            + " successfully");
                } else {
                    LOG.debug("Worker " + wi
                            + " Processed request successfully");
                }
            }

            // Old log entries (SignServer 3.1) added for backward compatibility
            // Log: REQUESTID
            if (res instanceof SignatureResponse) {
                logMap.put("REQUESTID", ((SignatureResponse) res).getRequestID());
            } else if (res instanceof DocumentValidationResponse) {
                logMap.put("REQUESTID", ((DocumentValidationResponse) res).getRequestID());
            }

            // Log
            final Object loggable = logMap.get(IWorkerLogger.LOG_PROCESS_SUCCESS);
            // log process status true if not already set by the worker...
            if (loggable == null) {
            	logMap.put(IWorkerLogger.LOG_PROCESS_SUCCESS, true);
            }
            workerLogger.log(adminInfo, logMap, requestContext);

            LOG.debug("<process");
            return res;

        } catch (WorkerLoggerException ex) {
            final SignServerException exception =
                    new SignServerException("Logging failed", ex);
            LOG.error(exception.getMessage(), exception);
            throw exception;
        } finally {
            // Check that the worker is behaving well and have returned all of
            // its aquired crypto instances
            final Collection<ICryptoInstance> cryptoInstances
                    = CryptoInstances.getInstance(requestContext).getAll();
            if (!cryptoInstances.isEmpty()) {
                LOG.warn("Worker " + wi + " did not release "
                        + cryptoInstances.size() + " crypto instances: "
                        + cryptoInstances);
            }
        }
    }

    private String generateTransactionID() {
        return UUID.randomUUID().toString();
    }

    private void logException(final AdminInfo adminInfo, final Exception ex, LogMap logMap,
    		IWorkerLogger workerLogger, RequestContext requestContext) throws WorkerLoggerException {
        if (workerLogger == null) {
            throw new WorkerLoggerException("Worker logger misconfigured", ex);
        }
    	logMap.put(IWorkerLogger.LOG_EXCEPTION, new ExceptionLoggable(ex));
    	logMap.put(IWorkerLogger.LOG_PROCESS_SUCCESS, false);
    	workerLogger.log(adminInfo, logMap, requestContext);
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
    private void checkSignerKeyUsageCounter(final Certificate cert,
            final int workerId, final long keyUsageLimit, EntityManager em,
            final boolean increment, final IServices services)
        throws CryptoTokenOfflineException {

        if (cert != null) {
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
                    CryptoTokenOfflineException ex = new CryptoTokenOfflineException(message);
                    LOG.error("Error while checking signer key usage counter", ex);
                    throw ex;
                }
            } else {
                // Just check the value without updating
                if (keyUsageLimit > -1) {
                    if (!keyUsageCounterDataService.isWithinLimit(keyHash, keyUsageLimit)) {
                        final String message
                                = "Key usage limit exceeded or not initialized for worker "
                                + workerId;
                        CryptoTokenOfflineException ex = new CryptoTokenOfflineException(message);
                        LOG.error("Error while checking signer key usage counter", ex);
                        throw ex;
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

    private static void handleArchiving(final Response res, final WorkerWithComponents worker, final RequestContext requestContext) throws SignServerException {
        if (res instanceof IArchivableProcessResponse) {
            final IArchivableProcessResponse arres = (IArchivableProcessResponse) res;
            final Collection<? extends Archivable> archivables = arres.getArchivables();
            if (archivables != null) {
                // Archive all Archivables using all ArchiverS
                final List<Archiver> archivers = worker.getArchivers();
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
    }

    private void handleAccounting(final WorkerWithComponents worker, final RequestContext requestContext, final LogMap logMap, final Request request, Response res, IWorkerLogger workerLogger, AdminInfo adminInfo) throws NotGrantedException, WorkerLoggerException, SignServerException {
        if (requestContext.isRequestFulfilledByWorker()) {
                
            // Billing time
            final boolean purchased;

            try {
                IClientCredential credential =
                        (IClientCredential) requestContext.get(
                                    RequestContext.CLIENT_CREDENTIAL);

                purchased = worker.getAccounter().purchase(credential, request, res, requestContext);

                logMap.put(IWorkerLogger.LOG_PURCHASED, purchased);
            } catch (AccounterException ex) {
                logMap.put(IWorkerLogger.LOG_PURCHASED, false);
                final SignServerException exception =
                        new SignServerException("Accounter failed: "
                        + ex.getMessage(), ex);
                logException(adminInfo, ex, logMap, workerLogger, requestContext);
                throw exception;
            }
            if (!purchased) {
                final String error = "Purchase not granted";
                logMap.put(IWorkerLogger.LOG_EXCEPTION, error);
                logMap.put(IWorkerLogger.LOG_PROCESS_SUCCESS, false);

                workerLogger.log(adminInfo, logMap, requestContext);
                throw new NotGrantedException(error);
            }
        } else {
            logMap.put(IWorkerLogger.LOG_PURCHASED, false);
        }
    }

    private void handleSignerCertificate(Certificate signerCertificate, int workerId, LogMap logMap, PreloadedWorkerConfig pwc, RequestContext requestContext, IWorkerLogger workerLogger, AdminInfo adminInfo) throws WorkerLoggerException, CryptoTokenOfflineException {
        if (signerCertificate instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate) signerCertificate;

            // Log client certificate
            logMap.put(IWorkerLogger.LOG_SIGNER_CERT_SUBJECTDN, new Loggable() {
                @Override
                public String toString() {
                    return cert.getSubjectDN().getName();
                }
            });     
            logMap.put(IWorkerLogger.LOG_SIGNER_CERT_ISSUERDN, new Loggable() {
                @Override
                public String toString() {
                    return cert.getIssuerDN().getName();
                }
            });     
            logMap.put(IWorkerLogger.LOG_SIGNER_CERT_SERIALNUMBER, new Loggable() {
                @Override
                public String toString() {
                    return cert.getSerialNumber().toString(16);
                }
            });

            try {
                // Check signer validity if configured to do so
                if (pwc.isCheckCertValidity() || pwc.isCheckPrivateKeyValidity()) {
                    // Check if the signer has a signer certificate and if that
                    // certificate have ok validity and private key usage periods.
                    ValidityTimeUtils.checkSignerValidity(new WorkerIdentifier(workerId), pwc.isCheckCertValidity(), pwc.isCheckPrivateKeyValidity(), pwc.getMinRemainingCertValidity(), cert);
                }

                // Check key usage limit (preliminary check only)
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Key usage counter disabled: " + pwc.isDisableKeyUsageCounter());
                }
                if (!pwc.isDisableKeyUsageCounter() || pwc.isKeyUsageLimitSpecified()) {
                    checkSignerKeyUsageCounter(signerCertificate, workerId, pwc.getKeyUsageLimit(), em,
                            false, requestContext.getServices());
                }
            } catch (CryptoTokenOfflineException ex) {
                final CryptoTokenOfflineException exception =
                        new CryptoTokenOfflineException(ex);
                logException(adminInfo, exception, logMap, workerLogger, requestContext);
                throw exception;
            }

        } else { // if (cert != null)
            if (LOG.isDebugEnabled()) {
                LOG.debug("Worker does not have a signing certificate. Worker: "
                        + workerId);
            }
        }
    }

    private void handleAuthorization(final IProcessable processable, final WorkerWithComponents worker, final Request request, final LogMap logMap, final AdminInfo adminInfo, final IWorkerLogger workerLogger, final RequestContext requestContext) throws WorkerLoggerException, AuthorizationRequiredException, AccessDeniedException, IllegalRequestException, SignServerException {
        // Check authorization
        logMap.put(IWorkerLogger.LOG_WORKER_AUTHTYPE, new Loggable() {
            @Override
            public String toString() {
                return processable.getAuthenticationType();
            }
        });
        
        try {
            IAuthorizer authorizer = worker.getAuthorizer();
            if (authorizer == null) {
                final SignServerException exception =
                    new SignServerException("Authorization misconfigured");
                logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED, false);
                logException(adminInfo, exception, logMap, workerLogger, requestContext);
                throw exception;
            } else {
                authorizer.isAuthorized(request, requestContext);
                logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED, true);
            }
        } catch (AuthorizationRequiredException | AccessDeniedException ex) {
            throw ex;
        } catch (IllegalRequestException ex) {
            final IllegalRequestException exception =
                    new IllegalRequestException("Authorization failed: "
                    + ex.getMessage(), ex);
            logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED, false);
            logException(adminInfo, ex, logMap, workerLogger, requestContext);
            throw exception;
        } catch (SignServerException ex) {
            final SignServerException exception =
                    new SignServerException("Authorization failed: "
                    + ex.getMessage(), ex);
            logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED, false);
            logException(adminInfo, ex, logMap, workerLogger, requestContext);
            throw exception;
        }
        
        // Log client certificate (if any)
        final Certificate clientCertificate = (Certificate)
                requestContext.get(RequestContext.CLIENT_CERTIFICATE);
        if (clientCertificate instanceof X509Certificate) {
            final X509Certificate cert = (X509Certificate) clientCertificate;
            logMap.put(IWorkerLogger.LOG_CLIENT_CERT_SUBJECTDN, new Loggable() {
                @Override
                public String toString() {
                    return cert.getSubjectDN().getName();
                }
            });

            logMap.put(IWorkerLogger.LOG_CLIENT_CERT_ISSUERDN, new Loggable() {
                @Override
                public String toString() {
                    return cert.getIssuerDN().getName();
                }
            });

            logMap.put(IWorkerLogger.LOG_CLIENT_CERT_SERIALNUMBER, new Loggable() {
                @Override
                public String toString() {
                    return cert.getSerialNumber().toString(16);
                }
            });     
        }
    }

    private Response handleProcessing(final IProcessable processable, final int workerId, final Request request, final RequestContext requestContext, final LogMap logMap, final IWorkerLogger workerLogger, final AdminInfo adminInfo) throws AuthorizationRequiredException, WorkerLoggerException, SignServerException, IllegalRequestException, CryptoTokenOfflineException {
        try {
            return processable.processData(request, requestContext);
        } catch (AuthorizationRequiredException ex) {
          throw ex; // This can happen in dispatching workers
        } catch (SignServerException e) {
            final SignServerException exception = new SignServerException(
                    "SignServerException calling signer with ID " + workerId
                    + " : " + e.getMessage(), e);
            LOG.error(exception.getMessage(), exception);
            logException(adminInfo, exception, logMap, workerLogger, requestContext);
            throw exception;
        } catch (IllegalRequestException ex) {
            final IllegalRequestException exception =
                    new IllegalRequestException(ex.getMessage());
                            if (LOG.isInfoEnabled()) {
                                    LOG.info("Illegal request calling signer with ID " + workerId
                    + " : " + ex.getMessage());
                            }
                            logException(adminInfo, exception, logMap, workerLogger, requestContext);
            throw exception;
        } catch (CryptoTokenOfflineException ex) {
            final CryptoTokenOfflineException exception =
                    new CryptoTokenOfflineException(ex);
            logException(adminInfo, exception, logMap, workerLogger, requestContext);
            throw exception;
        }
    }

}
