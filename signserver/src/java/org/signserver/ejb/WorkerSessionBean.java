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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.util.CertTools;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IArchivableProcessResponse;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignResponse;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerConstants;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IServiceTimerSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.AccounterException;
import org.signserver.server.BaseProcessable;
import org.signserver.server.IClientCredential;
import org.signserver.server.IProcessable;
import org.signserver.server.ISystemLogger;
import org.signserver.server.IWorker;
import org.signserver.server.IWorkerLogger;
import org.signserver.server.NotGrantedException;
import org.signserver.server.SignServerContext;
import org.signserver.server.SystemLoggerException;
import org.signserver.server.SystemLoggerFactory;
import org.signserver.server.WorkerFactory;
import org.signserver.server.WorkerLoggerException;
import org.signserver.server.KeyUsageCounter;
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

    private static final long serialVersionUID = 1L;
    
    /** Log4j instance for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerSessionBean.class);

    /** Audit logger. */
    private static final ISystemLogger AUDITLOG = SystemLoggerFactory
            .getInstance().getLogger(WorkerSessionBean.class);
    
    /** The local home interface of Worker Config entity bean. */
    private transient WorkerConfigDataService workerConfigService;
    
    /** The local home interface of archive entity bean. */
    private transient ArchiveDataService archiveDataService;

    @EJB
    private IGlobalConfigurationSession.ILocal globalConfigurationSession;

    @EJB
    private IServiceTimerSession.ILocal serviceTimerSession;

    @PersistenceContext(unitName = "SignServerJPA")
    EntityManager em;
    

    @PostConstruct
    public void create() {
        workerConfigService = new WorkerConfigDataService(em);
        archiveDataService = new ArchiveDataService(em);
    }

    /**
     * @see org.signserver.ejb.interfaces.IWorkerSession#process(int,
     * org.signserver.common.ISignRequest, java.security.cert.X509Certificate,
     * java.lang.String)
     */
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
        final Map<String, String> logMap = getLogMap(requestContext);
                
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
        logMap.put(IWorkerLogger.LOG_TIME, String.valueOf(startTime));
        logMap.put(IWorkerLogger.LOG_ID, transactionID);
        logMap.put(IWorkerLogger.LOG_WORKER_ID, String.valueOf(workerId));
        logMap.put(IWorkerLogger.LOG_CLIENT_IP,
                (String) requestContext.get(RequestContext.REMOTE_IP));

        // Get worker instance
        final IWorker worker = WorkerFactory.getInstance().getWorker(workerId,
                workerConfigService, globalConfigurationSession,
                new SignServerContext(em));

        if (worker == null) {
            final IllegalRequestException ex =
                    new IllegalRequestException("Non-existing workerId: "
                    + workerId);
            LOG.error(ex.getMessage(), ex); //TODO: Not really error more like 404 Not Found

            logMap.put(IWorkerLogger.LOG_EXCEPTION, ex.getMessage());
            try {
                AUDITLOG.log(logMap);
            } catch (SystemLoggerException ex2) {
                LOG.error("Audit log failure", ex2);
            }
            throw ex;
        }

        // Get worker log instance
        final IWorkerLogger workerLogger = WorkerFactory.getInstance().
                getWorkerLogger(workerId,
                worker.getStatus().getActiveSignerConfig(), em);

        if (LOG.isDebugEnabled()) {
            LOG.info("Worker[" + workerId + "]: " + "WorkerLogger: "
                    + workerLogger);
        }

        try {
            // Get processable
            if (!(worker instanceof IProcessable)) {
                final IllegalRequestException ex = new IllegalRequestException(
                        "Worker exists but isn't a processable: " + workerId);
                // auditLog(startTime, workerId, false, requestContext, ex);
                logMap.put(IWorkerLogger.LOG_EXCEPTION, ex.getMessage());
                workerLogger.log(logMap);
                throw ex;
            }
            final IProcessable processable = (IProcessable) worker;

            // Check authorization
            logMap.put(IWorkerLogger.LOG_WORKER_AUTHTYPE,
                    processable.getAuthenticationType());
            try {
                WorkerFactory.getInstance()
                        .getAuthenticator(workerId,
                            processable.getAuthenticationType(),
                            worker.getStatus().getActiveSignerConfig(),
                            em).isAuthorized(request, requestContext);
                logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED,
                        String.valueOf(true));
            } catch (AuthorizationRequiredException ex) {
                throw ex;
            } catch (IllegalRequestException ex) {
                final IllegalRequestException exception =
                        new IllegalRequestException("Authorization failed: "
                        + ex.getMessage(), ex);
                logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED,
                        String.valueOf(false));
                logMap.put(IWorkerLogger.LOG_EXCEPTION, ex.getMessage());
                workerLogger.log(logMap);
                throw exception;
            } catch (SignServerException ex) {
                final SignServerException exception =
                        new SignServerException("Authorization failed: "
                        + ex.getMessage(), ex);
                logMap.put(IWorkerLogger.LOG_CLIENT_AUTHORIZED,
                        String.valueOf(false));
                logMap.put(IWorkerLogger.LOG_EXCEPTION, ex.getMessage());
                workerLogger.log(logMap);
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
            final WorkerConfig awc =
                    processable.getStatus().getActiveSignerConfig();
            if (awc.getProperties().getProperty(SignServerConstants.DISABLED,
                    "FALSE").equalsIgnoreCase("TRUE")) {
                final CryptoTokenOfflineException exception =
                        new CryptoTokenOfflineException("Error Signer : "
                        + workerId
                        + " is disabled and cannot perform any signature operations");
                logMap.put(IWorkerLogger.LOG_EXCEPTION, exception.getMessage());
                workerLogger.log(logMap);
                throw exception;
            }

            // Check signer certificate
            try {
                // Check if the signer has a signer certificate and if that
                // certificate have ok validity and private key usage periods.
                checkCertificateValidity(workerId, awc, logMap);

                // Check key usage limit
                incrementAndCheckSignerKeyUsageCounter(processable, workerId,
                        awc, em);
            } catch (CryptoTokenOfflineException ex) {
                final CryptoTokenOfflineException exception =
                        new CryptoTokenOfflineException(ex);
                logMap.put(IWorkerLogger.LOG_EXCEPTION, ex.getMessage());
                workerLogger.log(logMap);
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
                logMap.put(IWorkerLogger.LOG_EXCEPTION, exception.getMessage());
                workerLogger.log(logMap);
                throw exception;
            } catch (IllegalRequestException ex) {
                final IllegalRequestException exception =
                        new IllegalRequestException(
                        "SignServerException calling signer with id " + workerId
                        + " : " + ex.getMessage(), ex);
                LOG.error(exception.getMessage(), exception);
                logMap.put(IWorkerLogger.LOG_EXCEPTION, exception.getMessage());
                workerLogger.log(logMap);
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

                    purchased = WorkerFactory.getInstance().getAccounter(workerId,
                                    worker.getStatus().getActiveSignerConfig(),
                                    em).purchase(credential, request, res,
                                            requestContext);

                    logMap.put(IWorkerLogger.LOG_PURCHASED, "true");
                } catch (AccounterException ex) {
                    logMap.put(IWorkerLogger.LOG_PURCHASED, "false");
                    final SignServerException exception =
                            new SignServerException("Accounter failed: "
                            + ex.getMessage(), ex);
                    logMap.put(IWorkerLogger.LOG_EXCEPTION, ex.getMessage());
                    workerLogger.log(logMap);
                    throw exception;
                }
                if (!purchased) {
                    final String error = "Purchase not granted";
                    logMap.put(IWorkerLogger.LOG_EXCEPTION, error);
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
                if (awc.getProperties().getProperty(SignServerConstants.ARCHIVE,
                        "FALSE").equalsIgnoreCase("TRUE")) {
                    if (arres.getArchiveData() != null) {
                        final String requestIP = (String)
                                requestContext.get(RequestContext.REMOTE_IP);
                        final X509Certificate clientCert = (X509Certificate)
                                requestContext.get(
                                    RequestContext.CLIENT_CERTIFICATE);
                        archiveDataService.create(
                                ArchiveDataVO.TYPE_RESPONSE,
                                workerId, arres.getArchiveId(), clientCert,
                                requestIP, arres.getArchiveData());
                    } else {
                        LOG.error("Error archiving response generated of signer "
                                + workerId
                                + ", archiving is not supported by signer.");
                    }
                }
            }

            // Statistics: end event
            StatisticsManager.endEvent(workerId, awc, em, event);

            // Output successfully
            if (res instanceof ISignResponse) {
                LOG.info("Worker " + workerId + " Processed request "
                        + ((ISignResponse) res).getRequestID()
                        + " successfully");
            } else {
                LOG.info("Worker " + workerId
                        + " Processed request successfully");
            }

            // Log
            logMap.put(IWorkerLogger.LOG_PROCESS_SUCCESS, String.valueOf(true));
            workerLogger.log(logMap);

            LOG.debug("<process");
            return res;

        } catch (WorkerLoggerException ex) {
            final SignServerException exception =
                    new SignServerException("Logging failed", ex);
            LOG.error(exception.getMessage(), exception);
            throw exception;
        }
    }

    /** Verify the certificate validity times and also that the PrivateKeyUsagePeriod is ok
     *
     * @param workerId
     * @param awc
     * @throws CryptoTokenOfflineException
     */
    private void checkCertificateValidity(final int workerId,
            final WorkerConfig awc, final Map<String, String> logMap)
            throws CryptoTokenOfflineException {
        boolean checkcertvalidity = awc.getProperties().getProperty(
                SignServerConstants.CHECKCERTVALIDITY, "TRUE").equalsIgnoreCase(
                "TRUE");
        boolean checkprivatekeyvalidity = awc.getProperties().getProperty(
                SignServerConstants.CHECKCERTPRIVATEKEYVALIDITY, "TRUE").
                equalsIgnoreCase("TRUE");
        int minremainingcertvalidity = Integer.valueOf(awc.getProperties().
                getProperty(SignServerConstants.MINREMAININGCERTVALIDITY, "0"));
        if (LOG.isDebugEnabled()) {
            LOG.debug("checkcertvalidity: " + checkcertvalidity);
            LOG.debug("checkprivatekeyvalidity: " + checkprivatekeyvalidity);
            LOG.debug("minremainingcertvalidity: " + minremainingcertvalidity);
        }

        if (checkcertvalidity || checkprivatekeyvalidity || (minremainingcertvalidity
                > 0)) {
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

                // Check regular certificate validity
                Date notBefore = cert.getNotBefore();
                Date notAfter = cert.getNotAfter();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("The signer certificate is valid from '"
                            + notBefore + "' until '" + notAfter + "'");
                }
                Date now = new Date();

                // Certificate validity period. Cert must not be expired.
                if (checkcertvalidity) {
                    if (now.before(notBefore)) {
                        String msg = "Error Signer " + workerId
                                + " have a signing certificate that is not valid until "
                                + notBefore;
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(msg);
                        }
                        throw new CryptoTokenOfflineException(msg);
                    }
                    if (now.after(notAfter)) {
                        String msg = "Error Signer " + workerId
                                + " have a signing certificate that expired at "
                                + notAfter;
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(msg);
                        }
                        throw new CryptoTokenOfflineException(msg);
                    }
                }

                // Private key usage period. Private key must not be expired
                if (checkprivatekeyvalidity) {
                    // Check privateKeyUsagePeriod of it exists
                    byte[] extvalue = cert.getExtensionValue(X509Extensions.PrivateKeyUsagePeriod.
                            getId());
                    if ((extvalue != null) && (extvalue.length > 0)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(
                                    "Found a PrivateKeyUsagePeriod in the signer certificate.");
                        }
                        try {
                            DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(
                                    extvalue)).readObject());
                            PrivateKeyUsagePeriod p = PrivateKeyUsagePeriod.
                                    getInstance((ASN1Sequence) new ASN1InputStream(
                                    new ByteArrayInputStream(oct.getOctets())).
                                    readObject());
                            if (p != null) {
                                notBefore = p.getNotBefore().getDate();
                                notAfter = p.getNotAfter().getDate();
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("The signer certificate has a private key usage period from '"
                                            + notBefore + "' until '" + notAfter
                                            + "'");
                                }
                                now = new Date();
                                if (now.before(notBefore)) {
                                    String msg = "Error Signer " + workerId
                                            + " have a private key that is not valid until "
                                            + notBefore;
                                    if (LOG.isDebugEnabled()) {
                                        LOG.debug(msg);
                                    }
                                    throw new CryptoTokenOfflineException(msg);
                                }
                                if (now.after(notAfter)) {
                                    String msg = "Error Signer " + workerId
                                            + " have a private key that expired at "
                                            + notAfter;
                                    if (LOG.isDebugEnabled()) {
                                        LOG.debug(msg);
                                    }
                                    throw new CryptoTokenOfflineException(msg);
                                }
                            }
                        } catch (IOException e) {
                            LOG.error(e);
                            CryptoTokenOfflineException newe =
                                    new CryptoTokenOfflineException(
                                    "Error Signer " + workerId
                                    + " have a problem with PrivateKeyUsagePeriod, check server log.");
                            newe.initCause(e);
                            throw newe;
                        } catch (ParseException e) {
                            LOG.error(e);
                            CryptoTokenOfflineException newe =
                                    new CryptoTokenOfflineException(
                                    "Error Signer " + workerId
                                    + " have a problem with PrivateKeyUsagePeriod, check server log.");
                            newe.initCause(e);
                            throw newe;
                        }
                    }
                } // if (checkprivatekeyvalidity)

                // Check remaining validity of certificate. Must not be too short.
                if (minremainingcertvalidity > 0) {
                    Calendar cal = Calendar.getInstance();
                    cal.add(Calendar.DAY_OF_MONTH, minremainingcertvalidity);
                    Date check = cal.getTime();
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Checking if signer certificate expires before: "
                                + check);
                    }
                    if (check.after(notAfter)) {
                        String msg = "Error Signer " + workerId
                                + " have a signing certificate that expires within "
                                + minremainingcertvalidity + " days.";
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(msg);
                        }
                        throw new CryptoTokenOfflineException(msg);
                    }
                }

            } else { // if (cert != null)
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Worker does not have a signing certificate. Worker: "
                            + workerId);
                }
            }
        } // if (checkcertvalidity || checkprivatekeyvalidity) {
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
    private void incrementAndCheckSignerKeyUsageCounter(final IProcessable worker,
            final int workerId, final WorkerConfig awc, EntityManager em)
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
                    = KeyUsageCounter.createKeyHash(cert.getPublicKey());

            if(LOG.isDebugEnabled()) {
                LOG.debug("Worker[" + workerId +"]: "
                        + "Key usage limit: " + keyUsageLimit);
                LOG.debug("Worker[" + workerId +"]: "
                        + "Key hash: " + keyHash);
            }

            final Query updateQuery;
            if (keyUsageLimit < 0) {
                updateQuery = em.createQuery("UPDATE KeyUsageCounter w SET w.counter = w.counter + 1 WHERE w.keyHash = :keyhash");
            } else {
                updateQuery = em.createQuery("UPDATE KeyUsageCounter w SET w.counter = w.counter + 1 WHERE w.keyHash = :keyhash AND w.counter < :limit");
                updateQuery.setParameter("limit", keyUsageLimit);
            }
            updateQuery.setParameter("keyhash", keyHash);


            if (updateQuery.executeUpdate() < 1) {
                final String message
                        = "Key usage limit exceeded or not initialized for worker "
                        + workerId;
                LOG.debug(message);
                throw new CryptoTokenOfflineException(message);
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
    public WorkerStatus getStatus(int workerId) throws InvalidWorkerIdException {
        IWorker worker = WorkerFactory.getInstance().getWorker(workerId,
                workerConfigService, globalConfigurationSession, new SignServerContext(
                em));
        if (worker == null) {
            throw new InvalidWorkerIdException("Given SignerId " + workerId
                    + " doesn't exist");
        }


        return worker.getStatus();
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#getWorkerId(java.lang.String)
     */
    public int getWorkerId(String signerName) {
        return WorkerFactory.getInstance().getWorkerIdFromName(signerName.
                toUpperCase(), workerConfigService, globalConfigurationSession, new SignServerContext(
                em));
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#reloadConfiguration(int)
     */
    public void reloadConfiguration(int workerId) {
        if (workerId == 0) {
            globalConfigurationSession.reload();
        } else {
            WorkerFactory.getInstance().reloadWorker(workerId,
                    workerConfigService, globalConfigurationSession, new SignServerContext(
                    em));

            // Try to insert a key usage counter entry for this worker's public
            // key
            // Get worker instance
            final IWorker worker = WorkerFactory.getInstance().getWorker(workerId,
                workerConfigService, globalConfigurationSession,
                new SignServerContext(em));
            if (worker instanceof BaseProcessable) {
                try {
                    final Certificate cert = ((BaseProcessable)worker)
                            .getSigningCertificate();
                    if (cert != null) {
                        final String keyHash = KeyUsageCounter
                                .createKeyHash(cert.getPublicKey());

                        KeyUsageCounter counter
                                = em.find(KeyUsageCounter.class, keyHash);

                        if (counter == null) {
                            counter = new KeyUsageCounter(keyHash);
                            em.persist(counter);
                        }
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Worker[" + workerId + "]: "
                                    + "key usage counter: " + counter.getCounter());
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

        if (workerId == 0 || globalConfigurationSession.getWorkers(
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
        IWorker worker = WorkerFactory.getInstance().getWorker(signerId,
                workerConfigService, globalConfigurationSession, new SignServerContext(
                em));
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
        IWorker worker = WorkerFactory.getInstance().getWorker(signerId,
                workerConfigService, globalConfigurationSession, new SignServerContext(
                em));
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

    /* (non-Javadoc)
     * @see org.signserver.ejb.IWorkerSession#getCurrentSignerConfig(int)
     */
    public WorkerConfig getCurrentWorkerConfig(int signerId) {
        return getWorkerConfig(signerId);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#setWorkerProperty(int, java.lang.String, java.lang.String)
     */
    public void setWorkerProperty(int workerId, String key, String value) {
        WorkerConfig config = getWorkerConfig(workerId);
        config.setProperty(key.toUpperCase(), value);
        workerConfigService.setWorkerConfig(workerId, config);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#removeWorkerProperty(int, java.lang.String)
     */
    public boolean removeWorkerProperty(int workerId, String key) {
        boolean result = false;
        WorkerConfig config = getWorkerConfig(workerId);

        result = config.removeProperty(key.toUpperCase());
        if (config.getProperties().size() == 0) {
            workerConfigService.removeWorkerConfig(workerId);
            LOG.debug("WorkerConfig is empty and therefore removed.");
        } else {
            workerConfigService.setWorkerConfig(workerId, config);
        }
        return result;
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
        workerConfigService.setWorkerConfig(signerId, config);
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
        workerConfigService.setWorkerConfig(signerId, config);
        return result;
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#getCertificateRequest(int, org.signserver.common.ISignerCertReqInfo)
     */
    public ICertReqData getCertificateRequest(int signerId,
            ISignerCertReqInfo certReqInfo) throws
            CryptoTokenOfflineException, InvalidWorkerIdException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getCertificateRequest: signerId=" + signerId);
        }
        IWorker worker = WorkerFactory.getInstance().getWorker(signerId,
                workerConfigService, globalConfigurationSession, new SignServerContext(
                em));
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

        ICertReqData ret = processable.genCertificateRequest(certReqInfo);
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getCertificateRequest: signerId=" + signerId);
        }
        return ret;
    }

    /**
     * @see org.signserver.ejb.interfaces.IWorkerSession#getSigningCertificate(int) 
     */
    public Certificate getSignerCertificate(final int signerId) throws CryptoTokenOfflineException {
        Certificate ret = null;
        final IWorker worker = WorkerFactory.getInstance().getWorker(signerId,
                workerConfigService, globalConfigurationSession,
                new SignServerContext(em));
        if (worker instanceof BaseProcessable) {
            ret = ((BaseProcessable) worker).getSigningCertificate();
        }
        return ret;
    }

    /**
     * @see org.signserver.ejb.interfaces.IWorkerSession#getSigningCertificateChain(int)
     */
    public List<Certificate> getSignerCertificateChain(final int signerId) throws CryptoTokenOfflineException {
        List<Certificate> ret = null;
        final IWorker worker = WorkerFactory.getInstance().getWorker(signerId,
                workerConfigService, globalConfigurationSession,
                new SignServerContext(em));
        if (worker instanceof BaseProcessable) {
            Collection<Certificate> certs = ((BaseProcessable) worker)
                    .getSigningCertificateChain();
            if (certs instanceof List) {
                ret = (List) certs;
            } else {
                ret = new LinkedList<Certificate>(certs);
            }
        }
        return ret;
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#destroyKey(int, int)
     */
    public boolean destroyKey(int signerId, int purpose) throws
            InvalidWorkerIdException {
        IWorker worker = WorkerFactory.getInstance().getWorker(signerId,
                workerConfigService, globalConfigurationSession, new SignServerContext(
                em));
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
    public void uploadSignerCertificate(int signerId, X509Certificate signerCert,
            String scope) {
        WorkerConfig config = getWorkerConfig(signerId);

        (new ProcessableConfig(config)).setSignerCertificate(signerCert, scope);
        workerConfigService.setWorkerConfig(signerId, config);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#uploadSignerCertificateChain(int, java.util.Collection, java.lang.String)
     */
    public void uploadSignerCertificateChain(int signerId,
            Collection<Certificate> signerCerts, String scope) {

        WorkerConfig config = getWorkerConfig(signerId);
        (new ProcessableConfig(config)).setSignerCertificateChain(signerCerts,
                scope);
        workerConfigService.setWorkerConfig(signerId, config);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#genFreeWorkerId()
     */
    public int genFreeWorkerId() {
        Collection<Integer> ids = globalConfigurationSession.getWorkers(
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
    public ArchiveDataVO findArchiveDataFromArchiveId(int signerId,
            String archiveId) {
        ArchiveDataVO retval = null;

        ArchiveDataBean adb = archiveDataService.findByArchiveId(
                ArchiveDataVO.TYPE_RESPONSE, signerId, archiveId);
        if (adb != null) {
            retval = adb.getArchiveDataVO();
        }

        return retval;
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#findArchiveDatasFromRequestIP(int, java.lang.String)
     */
    public List<ArchiveDataVO> findArchiveDatasFromRequestIP(int signerId,
            String requestIP) {
        ArrayList<ArchiveDataVO> retval = new ArrayList<ArchiveDataVO>();

        Collection<ArchiveDataBean> result = archiveDataService.findByRequestIP(
                ArchiveDataVO.TYPE_RESPONSE, signerId, requestIP);
        Iterator<ArchiveDataBean> iter = result.iterator();
        while (iter.hasNext()) {
            ArchiveDataBean next = iter.next();
            retval.add(next.getArchiveDataVO());
        }

        return retval;
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#findArchiveDatasFromRequestCertificate(int, java.math.BigInteger, java.lang.String)
     */
    public List<ArchiveDataVO> findArchiveDatasFromRequestCertificate(
            int signerId, BigInteger requestCertSerialnumber,
            String requestCertIssuerDN) {
        ArrayList<ArchiveDataVO> retval = new ArrayList<ArchiveDataVO>();

        Collection<ArchiveDataBean> result = archiveDataService.
                findByRequestCertificate(ArchiveDataVO.TYPE_RESPONSE, signerId, CertTools.
                stringToBCDNString(requestCertIssuerDN), requestCertSerialnumber.
                toString(16));
        Iterator<ArchiveDataBean> iter = result.iterator();
        while (iter.hasNext()) {
            ArchiveDataBean next = iter.next();
            retval.add(next.getArchiveDataVO());
        }

        return retval;
    }

    private WorkerConfig getWorkerConfig(int workerId) {
        WorkerConfig workerConfig =
                workerConfigService.getWorkerConfig(workerId);
        if (workerConfig == null) {
            workerConfigService.create(workerId, WorkerConfig.class.getName());
            workerConfig = workerConfigService.getWorkerConfig(workerId);
        }
        return workerConfig;
    }

    private String generateTransactionID() {
        return UUID.randomUUID().toString();
    }

    private Map<String, String> getLogMap(final RequestContext requestContext) {
        Map<String, String> logMap = (Map)
                requestContext.get(RequestContext.LOGMAP);
        if (logMap == null) {
            logMap = new HashMap<String, String>();
            requestContext.put(RequestContext.LOGMAP, logMap);
        }
        return logMap;
    }
}
