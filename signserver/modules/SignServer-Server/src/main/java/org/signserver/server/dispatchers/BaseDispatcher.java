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

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.SignServerConstants;
import org.signserver.common.StaticWorkerStatus;
import org.signserver.common.WorkerStatus;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.server.BaseProcessable;
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
    public WorkerStatus getStatus(final List<String> additionalFatalErrors) {
        final List<String> fatalErrors = new LinkedList<String>(additionalFatalErrors);
        fatalErrors.addAll(getFatalErrors());

        final List<WorkerStatusInfo.Entry> briefEntries = new LinkedList<WorkerStatusInfo.Entry>();
        final List<WorkerStatusInfo.Entry> completeEntries = new LinkedList<WorkerStatusInfo.Entry>();

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
            configValue.append("  ").append(key).append("=").append(properties.getProperty(key)).append("\n\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Active Properties are", configValue.toString()));

        // Clients
        final StringBuilder clientsValue = new StringBuilder();
        for (AuthorizedClient client : new ProcessableConfig(config).getAuthorizedClients()) {
            clientsValue.append("  ").append(client.getCertSN()).append(", ").append(properties.getProperty(client.getIssuerDN())).append("\n");
        }
        completeEntries.add(new WorkerStatusInfo.Entry("Active Authorized Clients are (Cert DN, IssuerDN)", clientsValue.toString()));

        return new StaticWorkerStatus(new WorkerStatusInfo(workerId, config.getProperty("NAME"), "Dispatcher", WorkerStatus.STATUS_ACTIVE, briefEntries, Collections.<String>emptyList(), completeEntries, config));
    }
}
