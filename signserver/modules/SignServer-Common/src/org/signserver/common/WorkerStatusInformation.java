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

import java.io.Serializable;

/**
 * Status information that can be obtained from workers.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class WorkerStatusInformation implements Serializable {
    private static final long serialVersionUID = 1L;

    private String offlineText;
    private String briefText;
    private String completeText;

    /**
     * @return null if worker online, otherwise an error message explaining why the worker is offline
     */
    public String getOfflineText() {
        return offlineText;
    }

    /**
     * @param offlineText Explanation for why the worker is offline or null if it is online
     */
    public void setOfflineText(String offlineText) {
        this.offlineText = offlineText;
    }
    
    /**
     * @return Short text with status information
     */
    public String getBriefText() {
        return briefText;
    }

    /**
     * @return The second part of the status text with more details.
     */
    public String getCompleteText() {
        return completeText;
    }

    /**
     * @param briefText Short text with status information
     */
    public void setBriefText(String briefText) {
        this.briefText = briefText;
    }

    /**
     * @param completeText The second part of the status text with more details.
     */
    public void setCompleteText(String completeText) {
        this.completeText = completeText;
    }
    
}
