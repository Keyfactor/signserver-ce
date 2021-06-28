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
package org.signserver.adminws;

import java.io.Serializable;
import java.util.Properties;
import org.signserver.common.WorkerStatus;

/**
 * Class holding a worker's status.
 *
 * @see WorkerStatus
 * @author Markus Kilås
 * @version $Id$
 */
public class WSWorkerStatus implements Serializable {

    /** serialVersionUID for this class. */
    private static final long serialVersionUID = 1;

    private String hostname;
    private Properties activeConfig;
    private int workerId;
    private String ok;
    private String statusText;
    private String completeStatusText;

    /** Default no-arg constructor. */
    public WSWorkerStatus() {
    }

    /**
     * Constructs an instance of WSWorkerStatus.
     * @param hostname server's hostname.
     * @param activeConfig the active configuration properties.
     * @param workerId id of worker.
     * @param ok if the crypto token is active.
     * @param statusText the status in text form.
     * @param completeStatusText the complete status in text form.
     */
    public WSWorkerStatus(final String hostname, final Properties activeConfig,
            final int workerId, final String ok, final String statusText,
            final String completeStatusText) {
        this.hostname = hostname;
        this.activeConfig = activeConfig;
        this.workerId = workerId;
        this.ok = ok;
        this.statusText = statusText;
        this.completeStatusText = completeStatusText;
    }

    public Properties getActiveConfig() {
        return activeConfig;
    }

    public void setActiveConfig(Properties activeConfig) {
        this.activeConfig = activeConfig;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getOk() {
        return ok;
    }

    public void setOk(String ok) {
        this.ok = ok;
    }

    public String getStatusText() {
        return statusText;
    }

    public void setStatusText(String statusText) {
        this.statusText = statusText;
    }

    public int getWorkerId() {
        return workerId;
    }

    public void setWorkerId(int workerId) {
        this.workerId = workerId;
    }

    public String getCompleteStatusText() {
        return completeStatusText;
    }

    public void setCompleteStatusText(String completeStatusText) {
        this.completeStatusText = completeStatusText;
    }
}
