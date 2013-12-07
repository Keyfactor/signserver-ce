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
import java.util.Enumeration;
import java.util.List;

/**
 * Class used when responding to the SignSession.getStatus() method, represents
 * the status of a specific service.
 *
 * @author Philip Vendil
 * @version $Id$
 */
public class ServiceStatus extends WorkerStatus {

    private static final long serialVersionUID = 1L;

    /** 
     * Main constuctor
     */
    public ServiceStatus(int workerId, List<String> fatalErrors, ServiceConfig config) {
        super(workerId, fatalErrors, config.getWorkerConfig());

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
        out.println("Status of Service with Id " + workerId + " is :\n");
        out.println("  Service was last run at : " + getLastRunDate() + "\n");

        if (complete) {
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
        }
    }

}
