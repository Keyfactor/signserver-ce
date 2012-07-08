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
import java.text.DateFormat;
import java.util.Date;

/**
 * Class used when responding to the SignSession.getStatus() method, represents
 * the status of a specific service.
 *
 * @author Philip Vendil
 * @version $Id$
 */
public class ServiceStatus extends WorkerStatus {

    private static final long serialVersionUID = 1L;
    private WorkerStatusInformation info;
    
    /** 
     * Main constuctor
     */
    public ServiceStatus(int workerId, ServiceConfig config) {
        super(workerId, config.getWorkerConfig());
    }

    public ServiceStatus(int workerId, ServiceConfig serviceConfig, WorkerStatusInformation info) {
        this(workerId, serviceConfig);
        this.info = info;
    }

    /**
     * @return the date this service was last run or an error message
     * if it has not run since the server started.
     */
    public String getLastRunDate() {
        Date lastRun = new ServiceConfig(activeconfig).getLastRunTimestamp();

        if (lastRun == null) {
            return "Service does not seem to have run since start or reload of the server.";
        }

        return DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(lastRun);
    }

    @Override
    public void displayStatus(int workerId, PrintStream out, boolean complete) {
        out.println(INDENT1 + "Service last run at: " + getLastRunDate());
        out.println();

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
        }
    }

    /**
     * The default behavior is not to check anything unless the worker indicates 
     * something in the offlineText.
     */
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
        return "Service";
    }
    
}
