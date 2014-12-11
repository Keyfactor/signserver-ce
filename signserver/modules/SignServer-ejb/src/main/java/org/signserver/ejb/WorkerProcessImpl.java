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
import org.signserver.common.ISignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.NotGrantedException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerConstants;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.worker.impl.IWorkerManagerSessionLocal;
import org.signserver.server.AccounterException;
import org.signserver.server.BaseProcessable;
import org.signserver.server.IClientCredential;
import org.signserver.server.IProcessable;
import org.signserver.server.IWorker;
import org.signserver.server.KeyUsageCounterHash;
import org.signserver.server.ValidityTimeUtils;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.ArchiveException;
import org.signserver.server.archive.Archiver;
import org.signserver.server.entities.IKeyUsageCounterDataService;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.SignServerEventTypes;
import org.signserver.server.log.SignServerModuleTypes;
import org.signserver.server.log.SignServerServiceTypes;
import org.signserver.server.log.WorkerLoggerException;
import org.signserver.server.statistics.Event;
import org.signserver.server.statistics.StatisticsManager;

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

    private final IGlobalConfigurationSession.ILocal globalConfigurationSession;

    private final IWorkerManagerSessionLocal workerManagerSession;

    private final SecurityEventsLoggerSessionLocal logSession;

    /**
     * Constructs a new instance of WorkerProcessImpl.
     * @param em The EntityManager (if used)
     * @param keyUsageCounterDataService The key usage counter data service
     * @param globalConfigurationSession The global configuration session
     * @param workerManagerSession The worker manager session
     * @param logSession The log session
     */
    public WorkerProcessImpl(EntityManager em, IKeyUsageCounterDataService keyUsageCounterDataService, IGlobalConfigurationSession.ILocal globalConfigurationSession, IWorkerManagerSessionLocal workerManagerSession, SecurityEventsLoggerSessionLocal logSession) {
        this.em = em;
        this.keyUsageCounterDataService = keyUsageCounterDataService;
        this.globalConfigurationSession = globalConfigurationSession;
        this.workerManagerSession = workerManagerSession;
        this.logSession = logSession;
    }

    /**
     * @see IWorkerSession#process(int, org.signserver.common.ProcessRequest, org.signserver.common.RequestContext)
     */
    public ProcessResponse process(int workerId, ProcessRequest request, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        return process(new AdminInfo("Client user", null, null), workerId, request, requestContext);
    }

    /**
     * @see IWorkerSession.ILocal#process(org.signserver.server.log.AdminInfo, int, org.signserver.common.ProcessRequest, org.signserver.common.RequestContext)
     */
    public ProcessResponse process(final AdminInfo adminInfo, final int workerId,
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
        requestContext.put(RequestContext.WORKER_ID, workerId);
        requestContext.put(RequestContext.TRANSACTION_ID, transactionID);
        requestContext.put(RequestContext.EM, em);
        logMap.put(IWorkerLogger.LOG_TIME, String.valueOf(startTime));
        logMap.put(IWorkerLogger.LOG_ID, transactionID);
        logMap.put(IWorkerLogger.LOG_WORKER_ID, String.valueOf(workerId));
        logMap.put(IWorkerLogger.LOG_CLIENT_IP,
                (String) requestContext.get(RequestContext.REMOTE_IP));

        // Get worker instance
        final IWorker worker = workerManagerSession.getWorker(workerId, globalConfigurationSession);

        if (worker == null) {
            NoSuchWorkerException ex = new NoSuchWorkerException(String.valueOf(workerId));
            Map<String, Object> details = new LinkedHashMap<String, Object>();
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
                logException(adminInfo, ex, logMap, workerLogger);
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
                logException(adminInfo, ex, logMap, workerLogger);
                throw exception;
            } catch (SignServerException ex) {
                final SignServerException exception =
                        new SignServerException("Authorization failed: "
                        + ex.getMessage(), ex);
                logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED,
                        String.valueOf(false));
                logException(adminInfo, ex, logMap, workerLogger);
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
                logException(adminInfo, exception, logMap, workerLogger);
                throw exception;
            }

            // Check signer certificate
            final boolean counterDisabled = awc.getProperties().getProperty(SignServerConstants.DISABLEKEYUSAGECOUNTER, "FALSE").equalsIgnoreCase("TRUE");
            final long keyUsageLimit;
            try {
                keyUsageLimit = Long.valueOf(awc.getProperty(SignServerConstants.KEYUSAGELIMIT, "-1"));
            } catch (NumberFormatException ex) {
                final SignServerException exception = new SignServerException("Incorrect value in worker property " + SignServerConstants.KEYUSAGELIMIT, ex);
                logException(adminInfo, exception, logMap, workerLogger);
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
                logException(adminInfo, exception, logMap, workerLogger);
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
                logException(adminInfo, exception, logMap, workerLogger);
                throw exception;
            } catch (IllegalRequestException ex) {
                final IllegalRequestException exception =
                        new IllegalRequestException(ex.getMessage());
				if (LOG.isInfoEnabled()) {
					LOG.info("Illegal request calling signer with id " + workerId
                        + " : " + ex.getMessage());
				}
				logException(adminInfo, exception, logMap, workerLogger);
                throw exception;
            } catch (CryptoTokenOfflineException ex) {
                final CryptoTokenOfflineException exception =
                        new CryptoTokenOfflineException(ex);
                logException(adminInfo, exception, logMap, workerLogger);
                throw exception;
            }

            // Charge the client if the request was successfull
            if (requestContext.isRequestFulfilledByWorker()) {

                // Billing time
                boolean purchased = false;
                try {
                    IClientCredential credential =
                            (IClientCredential) requestContext.get(
                                        RequestContext.CLIENT_CREDENTIAL);

                    purchased = workerManagerSession.getAccounter(workerId,
                                    awc).purchase(credential, request, res,
                                            requestContext);

                    logMap.put(IWorkerLogger.LOG_PURCHASED, String.valueOf(purchased));
                } catch (AccounterException ex) {
                    logMap.put(IWorkerLogger.LOG_PURCHASED, "false");
                    final SignServerException exception =
                            new SignServerException("Accounter failed: "
                            + ex.getMessage(), ex);
                    logException(adminInfo, ex, logMap, workerLogger);
                    throw exception;
                }
                if (!purchased) {
                    final String error = "Purchase not granted";
                    logMap.put(IWorkerLogger.LOG_EXCEPTION, error);
                    logMap.put(IWorkerLogger.LOG_PROCESS_SUCCESS, String.valueOf(false));
                    workerLogger.log(adminInfo, logMap);
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
            if (LOG.isDebugEnabled()) {
                if (res instanceof ISignResponse) {
                    LOG.debug("Worker " + workerId + " Processed request "
                            + ((ISignResponse) res).getRequestID()
                            + " successfully");
                } else {
                    LOG.debug("Worker " + workerId
                            + " Processed request successfully");
                }
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
            }
            workerLogger.log(adminInfo, logMap);

            LOG.debug("<process");
            return res;

        } catch (WorkerLoggerException ex) {
            final SignServerException exception =
                    new SignServerException("Logging failed", ex);
            LOG.error(exception.getMessage(), exception);
            throw exception;
        }
    }

    private String generateTransactionID() {
        return UUID.randomUUID().toString();
    }

    private void logException(final AdminInfo adminInfo, Exception ex, LogMap logMap,
    		IWorkerLogger workerLogger) throws WorkerLoggerException {
    	logMap.put(IWorkerLogger.LOG_EXCEPTION, ex.getMessage());
    	logMap.put(IWorkerLogger.LOG_PROCESS_SUCCESS, String.valueOf(false));
    	workerLogger.log(adminInfo, logMap);
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
        Certificate cert;

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

    private Certificate getSignerCertificate(final int signerId) throws CryptoTokenOfflineException {
        Certificate ret = null;
        final IWorker worker = workerManagerSession.getWorker(signerId, globalConfigurationSession);
        if (worker instanceof BaseProcessable) {
            ret = ((BaseProcessable) worker).getSigningCertificate();
        }
        return ret;
    }

    /**
     * @see org.signserver.ejb.interfaces.IWorkerSession#getWorkerId(java.lang.String)
     */
    public int getWorkerId(String signerName) {
        return workerManagerSession.getIdFromName(signerName, globalConfigurationSession);
    }

}
