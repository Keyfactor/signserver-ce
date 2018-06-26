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
package org.signserver.server.dispatchers;

import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.SignServerConstants;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.server.BaseProcessable;
import org.signserver.server.IServices;
import org.signserver.server.signers.BaseSigner;

/**
 * Base class that all dispatchers can extend to cover basic in common
 * functionality.
 *
 * @version $Id$
 */
public abstract class BaseDispatcher extends BaseProcessable {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(BaseSigner.class);

    /**
     * @param additionalFatalErrors
     * @return WorkerStatus
     * @see org.signserver.server.IProcessable#getStatus()
     */
    @Override
    public WorkerStatusInfo getStatus(final List<String> additionalFatalErrors, final IServices services) {
        final List<String> fatalErrors = new LinkedList<>(additionalFatalErrors);
        fatalErrors.addAll(getFatalErrors(services));

        final List<WorkerStatusInfo.Entry> briefEntries = new LinkedList<>();
        final List<WorkerStatusInfo.Entry> completeEntries = new LinkedList<>();

        // Worker status
        briefEntries.add(new WorkerStatusInfo.Entry("Worker status", fatalErrors.isEmpty() ? "Active" : "Offline"));

        // Disabled
        if ("TRUE".equalsIgnoreCase(config.getProperty(SignServerConstants.DISABLED))) {
            briefEntries.add(new WorkerStatusInfo.Entry("", "Signer is disabled"));
        }

        // Properties
        final StringBuilder configValue = new StringBuilder();
        Properties properties = config.getProperties();
        for (String key : properties.stringPropertyNames()) {
            final String value = WorkerConfig.shouldMaskProperty(key) ?
                                 WorkerConfig.WORKER_PROPERTY_MASK_PLACEHOLDER :
                                 properties.getProperty(key);
            configValue.append(key).append("=").append(value).append("\n\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Worker properties", configValue.toString()));

        // Clients
        final StringBuilder clientsValue = new StringBuilder();
        for (AuthorizedClient client : config.getAuthorizedClients()) {
            clientsValue.append("  ").append(client.getCertSN()).append(", ").append(properties.getProperty(client.getIssuerDN())).append("\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Authorized clients (serial number, issuer DN)", clientsValue.toString()));

        return new WorkerStatusInfo(workerId, config.getProperty("NAME"),
                                    "Dispatcher", WorkerStatus.STATUS_ACTIVE,
                                    briefEntries, fatalErrors, completeEntries,
                                    config);
    }
}
