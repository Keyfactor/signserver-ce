/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.common;

import java.io.PrintStream;
import java.util.Enumeration;
import java.util.Iterator;

/**
 * Status for Dispatcher.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DispatcherStatus extends WorkerStatus {
    private static final long serialVersionUID = 1L;
    
    private WorkerStatusInformation info;
    
    public DispatcherStatus(int workerId, WorkerConfig config) {
        super(workerId, config);
    }

    public DispatcherStatus(int workerId, WorkerConfig config, WorkerStatusInformation info) {
        this(workerId, config);
        this.info = info;
    }

    @Override
    public String isOK() {
        final String result;
        if (getActiveSignerConfig()
                .getProperty(SignServerConstants.DISABLED) != null
                && getActiveSignerConfig()
                .getProperty(SignServerConstants.DISABLED)
                .equalsIgnoreCase("TRUE")) {
            result = "Worker disabled";
        } else if (info != null && info.getOfflineText() != null) {
            result = info.getOfflineText();
        } else {
            result = null;
        }
        return result;
    }

    @Override
    public void displayStatus(int workerId, PrintStream out, boolean complete) {
        out.println("Status of Dispatcher with Id " + workerId + " is :\n"
                + "  SignToken Status : "
                + signTokenStatuses[isOK() == null ? 1 : 2] + " \n\n");
        
        if (info != null) {
            String briefText = info.getBriefText();
            if (briefText != null) {
                out.println(briefText);
                out.println();
            }
        }
        
        if (complete) {
            if (info != null) {
                String completeText = info.getCompleteText();
                if (completeText != null) {
                    out.println(completeText);
                    out.println();
                }
            }
            out.println("Active Properties are :");
            if (getActiveSignerConfig().getProperties().size() == 0) {
                out.println("  No properties exists in active configuration\n");
            }
            Enumeration<?> propertyKeys = getActiveSignerConfig()
                    .getProperties().keys();
            while (propertyKeys.hasMoreElements()) {
                String key = (String) propertyKeys.nextElement();
                out.println("  " + key + "=" + getActiveSignerConfig()
                        .getProperties().getProperty(key) + "\n");
            }
            out.println("\n");
            out.println("Active Authorized Clients are are (Cert DN, IssuerDN):");
            Iterator<?> iter = new ProcessableConfig(getActiveSignerConfig())
                    .getAuthorizedClients().iterator();
            while (iter.hasNext()) {
                AuthorizedClient client = (AuthorizedClient) iter.next();
                out.println("  " + client.getCertSN() + ", "
                        + client.getIssuerDN() + "\n");
            }
        }
    }
}
