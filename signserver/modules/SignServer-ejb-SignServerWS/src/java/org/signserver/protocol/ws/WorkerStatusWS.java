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
package org.signserver.protocol.ws;

/**
 * Class representing a WS representation of status of a worker in the system.
 * 
 * @author Philip Vendil 28 okt 2007
 * @version $Id: WorkerStatusWS.java 500 2009-04-22 12:10:07Z anatom $
 */
public class WorkerStatusWS {

    public static transient final String OVERALLSTATUS_ALLOK = "ALLOK";
    public static transient final String OVERALLSTATUS_ERROR = "ERROR";
    private String workerName;
    private String overallStatus;
    private String errormessage;

    /**
     * JAX-WS constructor
     */
    public WorkerStatusWS() {
    }

    /**
     * @param workerName worker name or id.
     * @param overallStatus the
     * @param errormessage the error message describing the problem
     * if not OVERALLSTATUS_ALLOK is returned
     */
    public WorkerStatusWS(String workerName, String overallStatus, String errormessage) {
        this.workerName = workerName;
        this.overallStatus = overallStatus;
        this.errormessage = errormessage;
    }

    /**
     *  constructor from auto generated class
     */
    /*
    public WorkerStatusWS(org.signserver.protocol.ws.gen.WorkerStatusWS workerStatusWS){
    setOverallStatus(workerStatusWS.getOverallStatus());
    setErrormessage(workerStatusWS.getErrormessage());
    }*/
    /**
     * 
     * @return status the overall status, one of the OVERALLSTATUS_ constants
     * indicating if this instance of the worker is ready to accept calls. In
     * that case is OVERALLSTATUS_ALLOK returned.
     */
    public String getOverallStatus() {
        return overallStatus;
    }

    /**
     * 
     * @param status the overall status, one of the OVERALLSTATUS_ constants
     * indicating if this instance of the worker is ready to accept calls.
     */
    public void setOverallStatus(String status) {
        this.overallStatus = status;
    }

    /**
     * 
     * @return The error message sent along the overall status
     */
    public String getErrormessage() {
        return errormessage;
    }

    /**
     * The error message sent along the overall status
     * @param errormessage
     */
    public void setErrormessage(String errormessage) {
        this.errormessage = errormessage;
    }

    /**
     * @return the workerName or workerId
     */
    public String getWorkerName() {
        return workerName;
    }

    /**
     * @param workerName the workerName or workerId
     */
    public void setWorkerName(String workerName) {
        this.workerName = workerName;
    }
}
