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
package org.signserver.module.renewal.service;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.cesecore.util.SimpleTime;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceContext;
import org.signserver.common.SignServerException;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.ejb.interfaces.WorkerSessionLocal;
import org.signserver.module.renewal.common.RenewalWorkerProperties;
import org.signserver.server.IServices;
import org.signserver.server.ServiceExecutionFailedException;
import org.signserver.server.WorkerContext;
import org.signserver.server.log.AdminInfo;
import org.signserver.server.timedservices.BaseTimedService;

/**
 * Timed service monitoring a number of workers and checks if they need to have
 * a new certificate, in which case a request to the worker's renewal worker
 * is sent.
 * <p>
 * The worker has the following worker properties:
 * </p>
 * <ul>
 *    <li>
 *        <b>WORKERS</b> = Comma-separated list of workers to check the
 * validity time for and request renewal for if needed. (Required)
 *    </li>
 * </ul>
 * 
 * <p>
 * The following properties are set in the workers being monitored:
 * </p>
 * <ul>
 *    <li>
 *        <b>RENEWWORKER</b> = Renewal worker (name) to send the renewal
 * request to.
 *    </li>
 *    <li>
 *        <b>RENEW_FORDEFAULTKEY</b> = If set to true the certificate request
 * is sent for the current DEFAULTKEY and no key generation is performed.
 *    </li>
 *    <li>
 *        <b>RENEW_MINREMAININGSIGNINGVALIDITY</b> = The minimum signing
 * validity that must remain for the worker without it to be up for renewal.
 * This value is expressed as a number of days, hours, minutes and milliseconds
 * on the form "*d *h *m *s *ms".
 *    </li>
 * </ul>
 * @author Markus Kilås
 * @version $Id$
 */
public class RenewalTimedService extends BaseTimedService {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(RenewalTimedService.class);
    
    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss,SSS");
    
    // Worker properties
    private static final String PROPERTY_WORKERS = "WORKERS";
    
    /**
     * When a signer has less this value for the _signing_ validity left it is
     * up for renewal.
     * Note that signing validity might be shorter than the certificate
     * validity due to privateKeyUsagePeriod extension or
     * MINREMININGCERTVALIDITY configuration.
     * The value is specified as a number of days, hours, minutes, seconds and
     * milliseconds.
     * @see SimpleTime
     */
    private static final String WORKERPROPERTY_RENEW_MINREMININGSIGNINGVALIDITY = "RENEW_MINREMAININGSIGNINGVALIDITY";

    /**
     * If set to true, no new key is generated and instead the DEFAULTKEY is
     * used.
     */
    private static final String WORKERPROPERTY_RENEW_FORDEFAULTKEY = "RENEW_FORDEFAULTKEY";
    
    private static final String SEPARATOR = ",";
    
    // Default values
    private static final String DEFAULT_WORKERPROPERTY_RENEW_MINREMAININGSIGNINGVALIDITY = "0d";
    private static final String DEFAULT_WORKERPROEPRTY_RENEW_FORDEFAULTKEY = Boolean.FALSE.toString();

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    /** List of worker names. */
    private List<String> workers = Collections.emptyList();

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        // Required property WORKERS (might be empty though)
        String value = config.getProperty(PROPERTY_WORKERS);
        if (value == null) {
            configErrors.add("Missing required property: " + PROPERTY_WORKERS);
        } else {
            final String[] parts = value.split(SEPARATOR);
            workers = new ArrayList<>(parts.length);
            for (String part : parts) {
                part = part.trim();
                if (!part.isEmpty()) {
                    workers.add(part);
                }
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Worker[" + workerId + "]: Workers to monitor: " + workers);
        }
    }

    @Override
    public void work(final ServiceContext context)
            throws ServiceExecutionFailedException {
        if (!configErrors.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Service is misconfigured");
            }
        }
        
        if (LOG.isTraceEnabled()) {
            LOG.trace(">work");
        }

        LOG.info("Worker[" + workerId + "]: Service called");

        final WorkerSessionLocal workerSession = context.getServices().get(WorkerSessionLocal.class);
        final ProcessSessionLocal processSession = context.getServices().get(ProcessSessionLocal.class);
        if (workerSession == null || processSession == null) {
            throw new ServiceExecutionFailedException("Unable to lookup internal session beans");
        }

        // Gather renewal statuses
        List<RenewalStatus> statuses = getRenewalStatuses(workers, new Date(), workerSession);

        // Process each worker up for renewal
        for (RenewalStatus status : statuses) {
            if (status.renew) {
                try {
                    if (renew(status.workerName, status.renewalWorker, status.forDefaultKey, processSession)) {
                        LOG.info("Renewed worker: " + status.workerName);
                    } else {
                        LOG.error("Renewal failed for worker: " + status.workerName);
                    }
                } catch (IllegalRequestException | CryptoTokenOfflineException | SignServerException ex) {
                    LOG.error("Error renewing worker: " + status.workerName + ": " + ex.getLocalizedMessage());
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Error renewing worker: " + status.workerName + ": " + ex.getLocalizedMessage(), ex);
                    }
                }
            } else if (status.error != null) {
                LOG.error("Unable to renew " + status.workerName + ": " + status.error);
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Renewal not needed for " + status.workerName + " until after " + status.renewalDate);
                }
            }
        }

        if (LOG.isTraceEnabled()) {
            LOG.trace("<work");
        }
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        // Add our errors to the list of errors
        final LinkedList<String> errors = new LinkedList<>(
                super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }
    
    private boolean renew(final String signer, final String renewalWorker, final boolean forDefaultKey, final ProcessSessionLocal processSession) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        final boolean result;

        if (renewalWorker == null || renewalWorker.isEmpty()) {
            LOG.error("Worker[" + workerId + "]: No renewal worker configured for worker " + signer);
            result = false;
        } else {
            final Properties properties = new Properties();
            properties.setProperty(RenewalWorkerProperties.REQUEST_WORKER, signer);
            properties.setProperty(RenewalWorkerProperties.REQUEST_FORDEFAULTKEY, String.valueOf(forDefaultKey));

            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to renew " + signer + " using renewal worker " + renewalWorker);
            }
            final ProcessResponse processResp
                    = processSession.process(new AdminInfo("Client user", null, null),
                            new WorkerIdentifier(renewalWorker),
                        new GenericPropertiesRequest(properties),
                        new RequestContext());
            if (processResp instanceof GenericPropertiesResponse) {
                final Properties response
                        = ((GenericPropertiesResponse) processResp)
                            .getProperties();
                result = RenewalWorkerProperties.RESPONSE_RESULT_OK.equals(response.getProperty(RenewalWorkerProperties.RESPONSE_RESULT));
                if (!result) {
                    LOG.error("Worker[" + workerId + "]: Renewal response for " + signer + " was " +  response.getProperty(RenewalWorkerProperties.RESPONSE_MESSAGE));
                }
            } else {
                LOG.error("Worker[" + workerId + "]: Unexpected response type from " + renewalWorker);
                result = false;
            }
        }
        return result;
    }
    
    @Override
    public WorkerStatus getStatus(List<String> additionalFatalErrors, final IServices services) {
                final List<String> fatalErrorsIncludingAdditionalErrors = new LinkedList<>(additionalFatalErrors);
        fatalErrorsIncludingAdditionalErrors.addAll(getFatalErrors(services));

        List<WorkerStatusInfo.Entry> briefEntries = new LinkedList<>();
        List<WorkerStatusInfo.Entry> completeEntries = new LinkedList<>();

        // Worker status
        briefEntries.add(new WorkerStatusInfo.Entry("Worker status", fatalErrorsIncludingAdditionalErrors.isEmpty() ? "Active" : "Offline"));
        briefEntries.add(new WorkerStatusInfo.Entry("Service was last run at", getLastRunDate()));

        // Properties
        final StringBuilder configValue = new StringBuilder();
        Properties properties = config.getProperties();
        for (String key : properties.stringPropertyNames()) {
            configValue.append("  ").append(key).append("=").append(properties.getProperty(key)).append("\n\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Active Properties are", configValue.toString()));
        
        // Renewal times for workers
        final StringBuilder renewalValue = new StringBuilder();

        final WorkerSessionLocal workerSession = services.get(WorkerSessionLocal.class);
        List<RenewalStatus> statuses = getRenewalStatuses(workers, new Date(), workerSession);
        for (RenewalStatus status : statuses) {
            renewalValue.append("- ").append(status.workerName).append(" (").append(status.workerId).append("): ");
            if (status.error != null) {
                renewalValue.append("Error: ").append(status.error);
            } else {
                renewalValue.append("Renewal after: ").append(SDF.format(status.renewalDate));
                if (status.renew) {
                    renewalValue.append(" (on next run)");
                }
                if (status.forDefaultKey) {
                    renewalValue.append(", without key generation");
                } else {
                    renewalValue.append(", with key generation");
                }
                if (status.renewalWorker != null) {
                    renewalValue.append(", using renewal worker \"").append(status.renewalWorker).append("\".");
                }
                    
            }
            renewalValue.append("\n");
        }

        completeEntries.add(new WorkerStatusInfo.Entry("Workers Renewal Prognose", renewalValue.toString()));

        return new StaticWorkerStatus(new WorkerStatusInfo(workerId, config.getProperty("NAME"), "Service", WorkerStatus.STATUS_ACTIVE, briefEntries, fatalErrorsIncludingAdditionalErrors, completeEntries, config));
    }
    
    /**
     * Query the status and the certificate for each provided worker and
     * construct a list of renewal statuses containing information about how
     * and when the renewal will be performed.
     *
     * @param workers list of worker names
     * @param now the current time
     * @param workerSession to use for getting worker information
     * @return list of renewal statuses
     */
    protected List<RenewalStatus> getRenewalStatuses(final List<String> workers, final Date now, final WorkerSessionLocal workerSession) {
        final ArrayList<RenewalStatus> result = new ArrayList<>(workers.size());
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Gathering renewal status for workers: " + workers);
        }

        for (String worker : workers) {
            final RenewalStatus status = new RenewalStatus(worker);
            try {
                status.workerId = workerSession.getWorkerId(worker);
                final WorkerConfig workerConfig = workerSession.getCurrentWorkerConfig(status.workerId);

                // Get renewal worker name
                status.renewalWorker = workerConfig.getProperty(RenewalWorkerProperties.WORKERPROPERTY_RENEWWORKER);

                // Get if key should be generated or not
                status.forDefaultKey = Boolean.parseBoolean(workerConfig.getProperty(WORKERPROPERTY_RENEW_FORDEFAULTKEY, DEFAULT_WORKERPROEPRTY_RENEW_FORDEFAULTKEY));
                
                if (status.renewalWorker == null) {
                    status.error = "Missing " + RenewalWorkerProperties.WORKERPROPERTY_RENEWWORKER + " property for worker.";
                } else {

                    // Check setting for signing validity left
                    final String renewWhenLessThan = workerConfig.getProperty(WORKERPROPERTY_RENEW_MINREMININGSIGNINGVALIDITY, DEFAULT_WORKERPROPERTY_RENEW_MINREMAININGSIGNINGVALIDITY);

                    final SimpleTime renewTime = SimpleTime.getInstance(renewWhenLessThan);
                    if (renewTime == null) {
                        status.error = "Incorrect " + WORKERPROPERTY_RENEW_MINREMININGSIGNINGVALIDITY + " property for worker.";
                    } else {

                        try {
                            final Date notAfter = workerSession.getSigningValidityNotAfter(new WorkerIdentifier(status.workerId));

                            Calendar cal2 = Calendar.getInstance();
                            cal2.setTime(notAfter);

                            // Account for the min signing validity left
                            cal2.setTimeInMillis(cal2.getTimeInMillis() - renewTime.getLong());
                            status.renewalDate = cal2.getTime();

                            status.renew = now.after(status.renewalDate);
                        } catch (org.signserver.common.CryptoTokenOfflineException ex) {
                            status.error = "Crypto token offline so we can not check certificate validity: " + ex.getLocalizedMessage();
                        }                    
                    }
                }
            } catch (InvalidWorkerIdException ex) {
                status.error = "No such worker: " + ex.getLocalizedMessage();
            }
            result.add(status);
        }
        return result;
    }
    
    /**
     * Holder for renewal status of a worker.
     * At minimum it will contain a worker name and either a error message or
     * more information about the renewal status.
     */
    public static class RenewalStatus {
        /** Id of the worker. */
        private int workerId;
        
        /** Name of the worker. */
        private final String workerName;
        
        /** Error message or null if none. */
        private String error;
        
        /** Date after which the worker should be up for renewal. */
        private Date renewalDate;
        
        /** The worker to use as renewal worker. */
        private String renewalWorker;
        
        /** True if the worker should be renewed on the next run. */
        private boolean renew;

        /** True if the default key should be used instead of generating a new. */
        private boolean forDefaultKey;

        public RenewalStatus(String workerName) {
            this.workerName = workerName;
        }

        public int getWorkerId() {
            return workerId;
        }

        public String getWorkerName() {
            return workerName;
        }

        public Date getRenewalDate() {
            return renewalDate;
        }

        public String getError() {
            return error;
        }

        public String getRenewalWorker() {
            return renewalWorker;
        }

        public boolean isRenew() {
            return renew;
        }
        
        public boolean isForDefaultKey() {
            return forDefaultKey;
        }

    }
}
