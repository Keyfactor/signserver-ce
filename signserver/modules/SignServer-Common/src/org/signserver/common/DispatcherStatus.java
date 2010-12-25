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

    public DispatcherStatus(int workerId, WorkerConfig config) {
        super(workerId, config);
    }

    @Override
    public String isOK() {
        if (getActiveSignerConfig()
                .getProperty(SignServerConstants.DISABLED) == null
                || !getActiveSignerConfig()
                .getProperty(SignServerConstants.DISABLED)
                .equalsIgnoreCase("TRUE")) {
            return null;
        } else {
            return "Worker disabled";
        }
    }

    @Override
    public void displayStatus(int workerId, PrintStream out, boolean complete) {
        out.println("Status of Dispatcher with Id " + workerId + " is :\n"
                + "  SignToken Status : "
                + signTokenStatuses[isOK() == null ? 1 : 2] + " \n\n");
        if (complete) {
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
