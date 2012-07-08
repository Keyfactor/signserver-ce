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

/**
 * Class used when responding to the SignSession.getStatus() method, represents
 * the status of a specific service.
 *
 * @version $Id$
 */
public class DefaultWorkerStatus extends WorkerStatus {

    private static final long serialVersionUID = 1L;

    private WorkerStatusInformation info;
    
    /** 
     * Main constuctor
     */
    public DefaultWorkerStatus(int workerId, WorkerConfig config) {
        super(workerId, config);

    }

    public DefaultWorkerStatus(int workerId, WorkerConfig config, WorkerStatusInformation info) {
        this(workerId, config);
        this.info = info;
    }

    @Override
    public void displayStatus(int workerId, PrintStream out, boolean complete) {
        out.println("Status of Worker with Id " + workerId + " is :\n");
        
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
        }
    }

    /**
     * The default behavior is not to check anything.
     */
    @Override
    public String isOK() {
        return null;
    }

    @Override
    public String getType() {
        return "Worker";
    }
    
}
