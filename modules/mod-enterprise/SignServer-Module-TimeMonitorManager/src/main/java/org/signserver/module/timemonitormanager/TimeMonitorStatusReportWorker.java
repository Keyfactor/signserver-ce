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
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerConstants;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.cryptotokens.NullCryptoToken;
import org.signserver.server.signers.BaseSigner;
import org.signserver.statusrepo.StatusRepositorySessionLocal;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.StatusName;

/**
 * Worker responding with the status of the TimeMonitor (if available).
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TimeMonitorStatusReportWorker extends BaseSigner {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeMonitorStatusReportWorker.class);

    private static final ICryptoTokenV4 CRYPTO_TOKEN = new NullCryptoToken(WorkerStatus.STATUS_ACTIVE);

    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
    }

    @Override
    public Response processData(Request signRequest, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        
        if (!(signRequest instanceof SignatureRequest)) {
            throw new IllegalRequestException("Received request was not of expected type.");
        }
        final SignatureRequest request = (SignatureRequest) signRequest;
        
        try (OutputStream out = request.getResponseData().getAsOutputStream()) {
            out.write(createReport(requestContext.getServices().get(StatusRepositorySessionLocal.class)).toString().getBytes(StandardCharsets.UTF_8));
            
            return new SignatureResponse(request.getRequestID(), request.getResponseData(), null, null, null, "text/plain");
        } catch (IOException ex) {
            throw new SignServerException("IO error", ex);
        }
    }

    private StringBuilder createReport(StatusRepositorySessionLocal statusRepository) {
        final StringBuilder buff = new StringBuilder();
        try {
            final StatusEntry entry = statusRepository.getValidEntry(StatusName.TIMEMONITOR_STATE.name());
            buff.append(entry == null ? "n/a" : entry.getValue());
        } catch (NoSuchPropertyException ex) {
            buff.append(ex.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug("No such status property", ex);
            }
        }
        return buff;
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
    protected List<String> getSignerCertificateFatalErrors(final IServices services) {
        // This worker does not require any signer certificate so don't
        // report any error about it.
        return Collections.emptyList();
    }

    @Override
    public WorkerStatusInfo getStatus(final List<String> additionalFatalErrors, final IServices services) {
                WorkerStatusInfo info;
        final List<String> fatalErrors = new LinkedList<>(additionalFatalErrors);
        fatalErrors.addAll(getFatalErrors(services));

        final List<WorkerStatusInfo.Entry> briefEntries = new LinkedList<>();
        final List<WorkerStatusInfo.Entry> completeEntries = new LinkedList<>();

        // Worker status
        final boolean active = fatalErrors.isEmpty();
        briefEntries.add(new WorkerStatusInfo.Entry("Worker status", active ? "Active" : "Offline"));

        // Disabled
        if ("TRUE".equalsIgnoreCase(config.getProperty(SignServerConstants.DISABLED))) {
            briefEntries.add(new WorkerStatusInfo.Entry("", "Worker is disabled"));
        }

        completeEntries.add(new WorkerStatusInfo.Entry("TimeMonitor State", createReport(services.get(StatusRepositorySessionLocal.class)).toString()));

        return new WorkerStatusInfo(workerId, config.getProperty("NAME"),
                                    "Worker",
                                    active ? WorkerStatus.STATUS_ACTIVE : WorkerStatus.STATUS_OFFLINE,
                                    briefEntries, fatalErrors, completeEntries,
                                    config);
    }
}
