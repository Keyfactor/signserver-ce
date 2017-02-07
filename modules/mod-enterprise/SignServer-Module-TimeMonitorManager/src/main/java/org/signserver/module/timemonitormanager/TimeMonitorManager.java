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
package org.signserver.module.timemonitormanager;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;
import javax.persistence.EntityManager;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerConstants;
import org.signserver.common.SignServerException;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.cryptotokens.NullCryptoToken;
import org.signserver.server.signers.BaseSigner;
import org.signserver.statusrepo.StatusRepositorySessionLocal;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.StatusName;
import org.signserver.timemonitor.common.TimeMonitorRuntimeConfig;
import org.signserver.timemonitor.common.TimeMonitorState;

/**
 * Worker for setting time-related status properties, querying for the current
 * TimeMonitor configuration and displaying the TimeMonitor state.
 *
 * See also the TimeMonitor manual.
 *
 * Request properties:
 * <i>x.VALUE</i> - Where x is a status property: Sets the value of the property
 * <i>x.EXPIRATION</i> - Where x is a status property: Sets the expiration time 
 * for x (x.VALUE must also be specified)
 * <i>CONFIG</i> - (optional) The callers current config version. If not equal
 * to the current version the current configuration will be returned.
 *
 * @author Markus Kilås
 * @version $Id: StatusPropertiesWorker.java 4701 2014-05-13 11:28:55Z netmackan $
 * @see StatusRepositorySessionLocal
 * @see GenericPropertiesRequest
 * @see GenericPropertiesResponse
 */
public class TimeMonitorManager extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeMonitorManager.class);

    private static final String UPDATE = "UPDATE";
    private static final String VALUE = "VALUE";
    private static final String EXPIRATION = "EXPIRATION";

    private static final ICryptoTokenV4 CRYPTO_TOKEN = new NullCryptoToken(WorkerStatus.STATUS_ACTIVE);

    private final String configVersion = Integer.toHexString(hashCode());
    private final HashMap<String, String> timemonitorConfig = new HashMap<>();

    private TimeMonitorRuntimeConfig runConfig;

    private static final FastDateFormat FDF = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ss,SSS");

    private LinkedList<String> configErrors;

    protected StatusRepositorySessionLocal getStatusRepository(IServices services) {
        return services.get(StatusRepositorySessionLocal.class);
    }

    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        configErrors = new LinkedList<>();

        for (final String key : config.getProperties().stringPropertyNames()) {
            if (key.startsWith(TimeMonitorRuntimeConfig.PREFIX_TIMEMONITOR) || key.startsWith(TimeMonitorRuntimeConfig.PREFIX_TIMESERVER)) {
                timemonitorConfig.put(key, config.getProperties().getProperty(key));
            }
        }

        runConfig = TimeMonitorRuntimeConfig.load(config.getProperties(), configErrors);

        timemonitorConfig.put(TimeMonitorRuntimeConfig.PROPERTY_CONFIG, configVersion);
    }

    @Override
    public Response processData(Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException("Received request was not of expected type.");
        }
        final SignatureRequest request = (SignatureRequest) signRequest;
        
        final ProcessResponse ret;
        final Properties requestProperties, responseProperties;
        final ReadableData requestData = request.getRequestData();
        final WritableData responseData = request.getResponseData();

        // Check that the request contains a valid request
        if (request instanceof SignatureRequest) {
            requestProperties = new Properties();
            try (InputStream in = requestData.getAsInputStream()) {
                requestProperties.load(in);
            } catch (IOException ex) {
                LOG.error("Error in request: " + requestContext.get(RequestContext.TRANSACTION_ID), ex);
                throw new IllegalRequestException("Error parsing request. " + "See server log for information.");
            }
        } else {
            throw new IllegalRequestException(
                "Received request was not of expected type.");
        }

        // Process the request
        responseProperties = process(requestProperties, requestContext.getServices());

        try (OutputStream out = responseData.getAsOutputStream()) {
            responseProperties.store(out, null);
        } catch (IOException ex) {
            LOG.error("Error constructing response for request: "
                    + requestContext.get(RequestContext.TRANSACTION_ID),
                    ex);
            throw new SignServerException("Error constructing response."
                    + "See server log for information.");
        }


        // The client can be charged for the request
        requestContext.setRequestFulfilledByWorker(true);

        return new SignatureResponse(request.getRequestID(),
                        responseData, null, null, null, "text/plain");
    }

    private Properties process(Properties requestData, IServices services) throws IllegalRequestException {
        try {
            Properties result = new Properties();

            final Set<StatusName> changed = EnumSet.noneOf(StatusName.class);

            // Request for newer configuration
            final String oldVersion = requestData.getProperty(TimeMonitorRuntimeConfig.PROPERTY_CONFIG);
            if (oldVersion != null && !oldVersion.equalsIgnoreCase(configVersion)) {
                result.putAll(timemonitorConfig);
            }

            // Set values
            for (Object k : requestData.keySet()) {
                String key = (String) k;
                if (key.endsWith("." + VALUE)) {
                    String name = key.substring(0, key.indexOf("." + VALUE));
                    String expiration = requestData.getProperty(name + "." + EXPIRATION);
                    try {
                        if (expiration == null) {
                            getStatusRepository(services).update(name, requestData.getProperty(key));
                        } else {
                            getStatusRepository(services).update(name, requestData.getProperty(key), Long.parseLong(expiration));
                        }
                        changed.add(StatusName.valueOf(name));
                    } catch (NumberFormatException ex) {
                        throw new IllegalRequestException("Illegal expiration value for property: " + name);
                    } catch (NoSuchPropertyException ex) {
                        throw new IllegalRequestException(ex.getMessage());
                    }
                }
            }

            // Get the current values for the valid properties
            for (StatusName get : changed) {
                StatusEntry entry = getStatusRepository(services).getValidEntry(get.name());
                if (entry != null) {
                    result.put(get.name() + "." + UPDATE, String.valueOf(entry.getUpdateTime()));
                }
            }

            return result;
        } catch (NoSuchPropertyException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    protected List<String> getSignerCertificateFatalErrors(final IServices services) {
        // This worker does not require any signer certificate so don't
        // report any error about it.
        return Collections.emptyList();
    }

    @Override
    public ICryptoTokenV4 getCryptoToken(final IServices services) throws SignServerException {
        ICryptoTokenV4 result = super.getCryptoToken(services);

        // Not configuring a crypto token for this worker is not a problem as
        // this worker does not use a crypto token. Instead a dummy instance
        // is returned.
        if (result == null) {
            result = CRYPTO_TOKEN;
        }

        return result;
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final LinkedList<String> errors = new LinkedList<>(super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

    @Override
    public WorkerStatusInfo getStatus(List<String> additionalFatalErrors, final IServices services) {
                WorkerStatusInfo info;
        final List<String> fatalErrors = new LinkedList<>(additionalFatalErrors);
        fatalErrors.addAll(getFatalErrors(services));

        final List<WorkerStatusInfo.Entry> briefEntries = new LinkedList<>();
        final List<WorkerStatusInfo.Entry> completeEntries = new LinkedList<>();
        final Map<String, StatusEntry> repoEntries = getStatusRepository(services).getAllEntries();
        final StatusEntry stateEntry = repoEntries.get(StatusName.TIMEMONITOR_STATE.name());
        final String timeMonitorValue;
        final String lastUpdateValue;
        final String timeStateValue;
        final String reportStateValue;
        final String leapStateValue;
        final String configUpdatedValue;
        final String offsetValue;
        final String queryTime1Value;
        final String queryTime2Value;
        final String reportTimeValue;
        final String totalRunTimeValue;

        final Date now = new Date();

        if (stateEntry == null) {
            timeMonitorValue = "Unavailable";
            lastUpdateValue = "n/a";
            timeStateValue = "n/a";
            reportStateValue = "n/a";
            leapStateValue = "n/a";
            configUpdatedValue = "n/a";
            offsetValue = "n/a";
            queryTime1Value = "n/a";
            queryTime2Value = "n/a";
            reportTimeValue = "n/a";
            totalRunTimeValue = "n/a";
        } else {
            final TimeMonitorState state = TimeMonitorState.fromStateLine(stateEntry.getValue());

            if (stateEntry.getExpirationTime() < now.getTime()) {
                timeMonitorValue = "Not running?";
            } else if (runConfig.isDisabled()) {
                timeMonitorValue = "Disabled";
            } else {
                timeMonitorValue = "Running";
            }

            lastUpdateValue = FDF.format(state.getLastUpdated());
            timeStateValue = state.getTimeState().name();
            reportStateValue = state.getReportState().name();
            leapStateValue = state.getLeapState().name();
            configUpdatedValue = configVersion.equals(state.getConfigVersion()) ? "Up to date" : "Outdated";
            offsetValue = String.format("%6d ms", state.getOffset());
            queryTime1Value = String.format("%6d ms", state.getQueryTime1());
            queryTime2Value = String.format("%6d ms", state.getQueryTime2());
            reportTimeValue = String.format("%6d ms", state.getReportTime());
            totalRunTimeValue = String.format("%6d ms", state.getQueryTime1() + state.getQueryTime2() + state.getReportTime());
        }

        // Worker status
        final boolean active = fatalErrors.isEmpty();
        briefEntries.add(new WorkerStatusInfo.Entry("Worker status", active ? "Active" : "Offline"));
        briefEntries.add(new WorkerStatusInfo.Entry("Time monitor", timeMonitorValue));

        if (stateEntry != null) {
            briefEntries.add(new WorkerStatusInfo.Entry("Last update", lastUpdateValue));
            briefEntries.add(new WorkerStatusInfo.Entry("Current time", FDF.format(now)));
            if (stateEntry.getExpirationTime() >= now.getTime()) {
                briefEntries.add(new WorkerStatusInfo.Entry("Time state", timeStateValue));
                briefEntries.add(new WorkerStatusInfo.Entry("Report state", reportStateValue));
                briefEntries.add(new WorkerStatusInfo.Entry("Leap state", leapStateValue));
                briefEntries.add(new WorkerStatusInfo.Entry("Configuration", configUpdatedValue));
            }
        }

        // Disabled
        if (Boolean.TRUE.toString().equalsIgnoreCase(config.getProperty(SignServerConstants.DISABLED))) {
            briefEntries.add(new WorkerStatusInfo.Entry("", "Worker is disabled"));
        }

        // More TimeMonitor status

        // Status Repository values
        final StringBuilder repo = new StringBuilder();
        final StatusEntry insyncEntry = repoEntries.get(StatusName.TIMESOURCE0_INSYNC.name());
        final StatusEntry leapEntry = repoEntries.get(StatusName.LEAPSECOND.name());
        final StatusEntry logEntry = repoEntries.get(StatusName.TIMEMONITOR_LOG.name());
        repo.append("TIMESOURCE0_INSYNC:        ");
        if (insyncEntry == null) {
            repo.append("n/a\n");
        } else {
            repo.append(insyncEntry.getValue());
            if (insyncEntry.getExpirationTime() < now.getTime()) {
                repo.append(", expired ");
                if (insyncEntry.getExpirationTime() > 0) {
                    repo.append(FDF.format(insyncEntry.getExpirationTime()));
                }
            }
            repo.append("\n");
        }
        repo.append("LEAPSECOND:                ");
        if (leapEntry == null) {
            repo.append("n/a\n");
        } else {
            repo.append(leapEntry.getValue());
            if (leapEntry.getExpirationTime() < now.getTime()) {
                repo.append(", expired ").append(FDF.format(leapEntry.getExpirationTime()));
            }
            repo.append("\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Status Repository values", repo.toString()));

        // Timings
        final StringBuilder timings = new StringBuilder();
        if (stateEntry != null && stateEntry.getExpirationTime() >= now.getTime()) {
            if (!runConfig.isDisabled()) {
                timings.append("NTP server time offset:      ").append(offsetValue).append("\n");
                timings.append("NTP server query time:       ").append(queryTime1Value).append("\n");
                timings.append("NTP leap status query time:  ").append(queryTime2Value).append("\n");
            }
            timings.append("Report time:                 ").append(reportTimeValue).append("\n");
            if (!runConfig.isDisabled()) {
                timings.append("Total required run time:     ").append(totalRunTimeValue).append("\n");
            }
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Timings", timings.toString()));

        // Configuration
        final StringBuilder configs = new StringBuilder();
        configs.append("NTP server hosts:            ").append(String.format("%6s", runConfig.getTimeServerHost())).append("\n");
        configs.append("NTP query samples:           ").append(String.format("%6d", runConfig.getTimeServerSendSamples())).append("\n");
        configs.append("NTP query timeout:           ").append(String.format("%6d ms", (int) (runConfig.getTimeServerTimeout() * 1000d))).append("\n");
        configs.append("Max accepted offset:         ").append(String.format("%6d ms", runConfig.getMaxAcceptedOffset())).append("\n");
        configs.append("Warn offset:                 ").append(String.format("%6d ms", runConfig.getWarnOffset())).append("\n");
        configs.append("Status expire time:          ").append(String.format("%6d ms", runConfig.getStatusExpireTime())).append("\n");
        configs.append("Leap status expire time:     ").append(String.format("%6d ms", runConfig.getLeapStatusExpireTime())).append("\n");
        configs.append("Warn run time:               ").append(String.format("%6d ms", runConfig.getWarnRunTime())).append("\n");
        configs.append("Minimum run time:            ").append(String.format("%6d ms", runConfig.getMinRunTime())).append("\n");

        completeEntries.add(new WorkerStatusInfo.Entry("Configuration", configs.toString()));

        completeEntries.add(new WorkerStatusInfo.Entry("Last TimeMonitor log entries", logEntry == null ? "n/a" : logEntry.getValue()));

        return new WorkerStatusInfo(workerId, config.getProperty("NAME"),
                                    "Worker",
                                    active ? WorkerStatus.STATUS_ACTIVE : WorkerStatus.STATUS_OFFLINE,
                                    briefEntries, fatalErrors, completeEntries,
                                    config);
    }

}
