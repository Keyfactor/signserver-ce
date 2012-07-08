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
package org.signserver.common;

import java.io.PrintStream;
import java.util.Enumeration;
import java.util.Iterator;

/**
 * Class used when responding to the SignSession.getStatus() method, represents
 * the status of a specific validator.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class ValidatorStatus extends WorkerStatus {

    private static final long serialVersionUID = 1L;
    
    private WorkerStatusInformation info;

    /** 
     * Main constructor
     */
    public ValidatorStatus(int workerId, ProcessableConfig config) {
        super(workerId, config.getWorkerConfig());
    }

    public ValidatorStatus(int workerId, ProcessableConfig processableConfig, WorkerStatusInformation info) {
        this(workerId, processableConfig);
        this.info = info;
    }

    @Override
    public void displayStatus(int workerId, PrintStream out, boolean complete) {
        out.println("Status of Validator with Id " + workerId + " is :\n"
                + "  SignToken Status : " + " \n\n");
        
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

            Enumeration<?> propertyKeys = getActiveSignerConfig().getProperties().keys();
            while (propertyKeys.hasMoreElements()) {
                String key = (String) propertyKeys.nextElement();
                out.println("  " + key + "=" + getActiveSignerConfig().getProperties().getProperty(key) + "\n");
            }

            out.println("\n");

            out.println("Active Authorized Clients are are (Cert DN, IssuerDN):");
            Iterator<?> iter = new ProcessableConfig(getActiveSignerConfig()).getAuthorizedClients().iterator();
            while (iter.hasNext()) {
                AuthorizedClient client = (AuthorizedClient) iter.next();
                out.println("  " + client.getCertSN() + ", " + client.getIssuerDN() + "\n");
            }
            // Validator specific status information can be added here
        }
    }

    @Override
    public String isOK() {
        final String result;
        if (info != null && info.getOfflineText() != null) {
            result = info.getOfflineText();
        } else {
            result = null;
        }
        return result;
    }

    @Override
    public String getType() {
        return "Validator";
    }
    
}
