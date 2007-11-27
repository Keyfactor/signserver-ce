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
 *
 * @version $Id: WorkerStatusWS.java,v 1.1 2007-11-27 06:05:07 herrvendil Exp $
 */

public class WorkerStatusWS {
	
	public static transient final String OVERALLSTATUS_ALLOK = "ALLOK";
	public static transient final String OVERALLSTATUS_ERROR = "ERROR";
	
	private String overallStatus;
	private String errormessage;
	
	/**
	 * JAX-WS constructor
	 */
	public WorkerStatusWS(){
		
	}
	
	/**
	 * 
	 * @param overallStatus the
	 * @param errormessage the error message describing the problem
	 * if not OVERALLSTATUS_ALLOK is returned
	 */
	public WorkerStatusWS(String overallStatus, String errormessage){
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
	
	
	
	

}
