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
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
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
import org.signserver.common.KeyTestResult;
import org.signserver.common.NoSuchWorkerException;
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
import org.signserver.server.IWorker;
import org.signserver.server.KeyUsageCounter;
import org.signserver.server.NotGrantedException;
import org.signserver.server.SignServerContext;
import org.signserver.server.WorkerFactory;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.ArchiveException;
import org.signserver.server.archive.Archiver;
import org.signserver.server.archive.olddbarchiver.ArchiveDataArchivable;
import org.signserver.server.archive.olddbarchiver.ArchiveDataBean;
import org.signserver.server.archive.olddbarchiver.ArchiveDataService;
import org.signserver.server.log.ISystemLogger;
import org.signserver.server.log.IWorkerLogger;
import org.signserver.server.log.SystemLoggerException;
import org.signserver.server.log.SystemLoggerFactory;
import org.signserver.server.log.WorkerLoggerException;
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
    private WorkerConfigDataService workerConfigService;
    
    /** The local home interface of archive entity bean. */
    private ArchiveDataService archiveDataService;

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
        requestContext.put(RequestContext.WORKER_ID, Integer.valueOf(workerId));
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
                    new NoSuchWorkerException(String.valueOf(workerId));

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
            LOG.debug("Worker[" + workerId + "]: " + "WorkerLogger: "
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
                checkSignerValidity(workerId, awc, logMap);

                // Check key usage limit (preliminary check only)
                checkSignerKeyUsageCounter(processable, workerId, awc, em,
                        false);
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
                        new IllegalRequestException(ex.getMessage());
                LOG.error("Error calling signer with id " + workerId
                        + " : " + ex.getMessage(), exception);
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
                if (arres.getArchiveData() != null) {
                    // The IArchivableProcessResponse only supports a single
                    // item to archive. In the future we might get multiple
                    // Archivables from a worker.
                    final Archivable archivableResponse
                            = new ArchiveDataArchivable(arres.getArchiveId(), 
                                arres.getArchiveData(), Archivable.TYPE_RESPONSE);
                    final Collection<Archivable> archivables
                            = Collections.singleton(archivableResponse);

                    // Archive all Archivables using all ArchiverS
                    final List<Archiver> archivers = WorkerFactory
                           .getInstance().getArchivers(workerId, awc, em);
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
                                    "Archiving failed. See server log.");
                        }
                    }
                }
            }

            // Statistics: end event
            StatisticsManager.endEvent(workerId, awc, em, event);

            // Check key usage limit
            checkSignerKeyUsageCounter(processable, workerId, awc, em, true);

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

    /**
     * Verify the certificate validity times, the PrivateKeyUsagePeriod and
     * that the minremaining validity is ok.
     *
     * @param workerId
     * @param awc
     * @throws CryptoTokenOfflineException
     */
    private void checkSignerValidity(final int workerId,
            final WorkerConfig awc, final Map<String, String> logMap)
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

            // Check certificate, privatekey and minremaining validities
            final Date notBefore =
                    getSigningValidity(false, workerId, awc, cert);
            final Date notAfter =
                    getSigningValidity(true, workerId, awc, cert);
            if (LOG.isDebugEnabled()) {
                LOG.debug("The signer validity is from '"
                        + notBefore + "' until '" + notAfter + "'");
            }

            // Compare with current date
            final Date now = new Date();
            if (notBefore != null && now.before(notBefore)) {
                final String msg = "Error Signer " + workerId
                        + " is not valid until " + notBefore;
                if (LOG.isDebugEnabled()) {
                    LOG.debug(msg);
                }
                throw new CryptoTokenOfflineException(msg);
            }
            if (notAfter != null && now.after(notAfter)) {
                String msg = "Error Signer " + workerId
                        + " expired at " + notAfter;
                if (LOG.isDebugEnabled()) {
                    LOG.debug(msg);
                }
                throw new CryptoTokenOfflineException(msg);
            }
        } else { // if (cert != null)
            if (LOG.isDebugEnabled()) {
                LOG.debug("Worker does not have a signing certificate. Worker: "
                        + workerId);
            }
        }
        
    } // checkCertificateValidity

    private static PrivateKeyUsagePeriod getPrivateKeyUsagePeriod(
            final X509Certificate cert) throws IOException {
        PrivateKeyUsagePeriod res = null;
        final byte[] extvalue = cert.getExtensionValue(
                X509Extensions.PrivateKeyUsagePeriod.getId());
        
        if ((extvalue != null) && (extvalue.length > 0)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(
                    "Found a PrivateKeyUsagePeriod in the signer certificate.");
            }
            final DEROctetString oct = (DEROctetString) (new ASN1InputStream(
                    new ByteArrayInputStream(extvalue)).readObject());

            res = PrivateKeyUsagePeriod.
                    getInstance((ASN1Sequence) new ASN1InputStream(
                    new ByteArrayInputStream(oct.getOctets())).
                    readObject());
        }
        return res;
    }

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
            date = getSigningValidity(true, workerId,
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
            date = getSigningValidity(false, workerId,
                    getWorkerConfig(workerId), cert);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Worker does not have a signing certificate. Worker: "
                        + workerId);
            }
        }
        return date;
    }

    private Date getSigningValidity(final boolean notAfter, final int workerId,
            final WorkerConfig awc, final X509Certificate cert)
            throws CryptoTokenOfflineException {
        Date certDate = null;
        Date privatekeyDate = null;
        Date minreimainingDate = null;

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

        // Certificate validity period. Cert must not be expired.
        if (checkcertvalidity) {
            certDate = notAfter ? cert.getNotAfter() : cert.getNotBefore();
        }

        // Private key usage period. Private key must not be expired
        if (checkprivatekeyvalidity) {
            // Check privateKeyUsagePeriod of it exists
            try {
                final PrivateKeyUsagePeriod p = getPrivateKeyUsagePeriod(cert);
                if (p != null) {
                    privatekeyDate = notAfter ? p.getNotAfter().getDate()
                            : p.getNotBefore().getDate();
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

        // Check remaining validity of certificate. Must not be too short.
        if (notAfter && minremainingcertvalidity > 0) {
            final Date certNotAfter = cert.getNotAfter();
            final Calendar cal = Calendar.getInstance();
            cal.setTime(certNotAfter);
            cal.add(Calendar.DAY_OF_MONTH, -minremainingcertvalidity);
            minreimainingDate = cal.getTime();
        }

        Date res = null;

        res = certDate;
        res = max(notAfter, res, privatekeyDate);
        res = max(notAfter, res, minreimainingDate);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug((notAfter ? "min(" : "max(") + certDate + ", "
                    + privatekeyDate + ", " + minreimainingDate + ") = "
                    + res);
        }
        return res;
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
                        = KeyUsageCounter.createKeyHash(cert.getPublicKey());
                final KeyUsageCounter signings
                        = em.find(KeyUsageCounter.class, pk);
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
     * @param inv If the max function should be inverrted (min).
     * @param date1 Operand 1
     * @param date2 Operand 2
     * @return The last of the two dates unless inv is true in which case it
     * returns the first of the two.
     */
    private static Date max(final boolean inv, final Date date1,
            final Date date2) {
        if (date1 == null) {
            return date2;
        } else if (date2 == null) {
            return date1;
        }
        return inv && date1.before(date2) ? date1 : date2;
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
                    = KeyUsageCounter.createKeyHash(cert.getPublicKey());

            if(LOG.isDebugEnabled()) {
                LOG.debug("Worker[" + workerId +"]: "
                        + "Key usage limit: " + keyUsageLimit);
                LOG.debug("Worker[" + workerId +"]: "
                        + "Key hash: " + keyHash);
            }

            if (increment) {
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
                // Just check the value without updating
                if (keyUsageLimit > -1) {
                    final Query selectQuery;
                    selectQuery = em.createQuery("SELECT COUNT(w) FROM KeyUsageCounter w WHERE w.keyHash = :keyhash AND w.counter < :limit");
                    selectQuery.setParameter("limit", keyUsageLimit);
                    selectQuery.setParameter("keyhash", keyHash);

                    if (selectQuery.getResultList().size() < 1) {
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

    /**
     * @see IWorkerSession#generateSignerKey(int, java.lang.String,
     *  java.lang.String, java.lang.String, char[])
     */
    public String generateSignerKey(final int signerId, String keyAlgorithm,
            String keySpec, String alias, final char[] authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
                IllegalArgumentException {

        IWorker worker = WorkerFactory.getInstance().getWorker(signerId,
                workerConfigService, globalConfigurationSession,
                new SignServerContext(em));
        if (worker == null) {
            throw new InvalidWorkerIdException("Given SignerId " + signerId
                    + " doesn't exist");
        }

        if (!(worker instanceof IProcessable)) {
            throw new InvalidWorkerIdException(
                    "Worker exists but isn't a signer.");
        }
        final IProcessable signer = (IProcessable) worker;

        final WorkerConfig config = worker.getStatus().getActiveSignerConfig();

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
    public Collection<KeyTestResult> testKey(final int signerId, String alias,
            char[] authCode)
            throws CryptoTokenOfflineException, InvalidWorkerIdException,
            KeyStoreException {

        IWorker worker = WorkerFactory.getInstance().getWorker(signerId,
                workerConfigService, globalConfigurationSession,
                new SignServerContext(em));
        if (worker == null) {
            throw new InvalidWorkerIdException("Given SignerId " + signerId
                    + " doesn't exist");
        }

        if (!(worker instanceof IProcessable)) {
            throw new InvalidWorkerIdException(
                    "Worker exists but isn't a signer.");
        }
        final IProcessable signer = (IProcessable) worker;
        
//        if (worker.getStatus().isOK() != null) {
//            throw new CryptoTokenOfflineException(
//                    "Testing key can not be performed on offline cryptotoken");
//        }

        final WorkerConfig config = worker.getStatus().getActiveSignerConfig();

        if (alias == null) {
            alias = config.getProperty("DEFAULTKEY");
        }

        return signer.testKey(alias, authCode);
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
    public ICertReqData getCertificateRequest(int signerId,
            ISignerCertReqInfo certReqInfo,
            final boolean explicitEccParameters,
            final boolean defaultKey) throws
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

        ICertReqData ret = processable.genCertificateRequest(certReqInfo,
                explicitEccParameters, defaultKey);
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
    public List<Certificate> getSignerCertificateChain(final int signerId)
            throws CryptoTokenOfflineException {
        List<Certificate> ret = null;
        final IWorker worker = WorkerFactory.getInstance().getWorker(signerId,
                workerConfigService, globalConfigurationSession,
                new SignServerContext(em));
        if (worker instanceof BaseProcessable) {
            Collection<Certificate> certs = ((BaseProcessable) worker)
                    .getSigningCertificateChain();
            if (certs instanceof List) {
                ret = (List) certs;
            } else if( certs != null) {
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
    public void uploadSignerCertificate(int signerId, byte[] signerCert,
            String scope) throws CertificateException {
        WorkerConfig config = getWorkerConfig(signerId);

        final Certificate cert  = CertTools.getCertfromByteArray(signerCert);
        ( new ProcessableConfig(config)).setSignerCertificate((X509Certificate)cert,scope);
        workerConfigService.setWorkerConfig(signerId, config);
    }

    /* (non-Javadoc)
     * @see org.signserver.ejb.interfaces.IWorkerSession#uploadSignerCertificateChain(int, java.util.Collection, java.lang.String)
     */
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
