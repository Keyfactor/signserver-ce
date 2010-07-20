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
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;

/**
 * Common base class used to report the status of a signer or service. Should
 * be inherited by all workers.
 * 
 * @author Philip Vendil
 *
 * $Id$
 */

public abstract class WorkerStatus implements Serializable{

	protected static final String[] signTokenStatuses = {"", "Active", "Offline"};
	
	private static final long serialVersionUID = 1L;

	protected String hostname = null;
	protected WorkerConfig activeconfig= null;	
    protected int workerId;
	
	/** 
	 * Main constuctor
	 */
	public WorkerStatus(int workerId, WorkerConfig config){
		this.workerId = workerId;
	    try {
	    	hostname= InetAddress.getLocalHost().getHostName();
	    } catch (UnknownHostException e) {
	    	hostname= "unknown";
	    }
	    activeconfig = config;
	}

	/**
	 * @return Returns the workerId.
	 */
	public int getWorkerId(){
		return workerId;
	}

	/**
	 * @return Returns the hostname.
	 */
	public String getHostname() {
		return hostname;
	}
	
	public WorkerConfig getActiveSignerConfig(){
		return activeconfig;
	}
	
	/**
	 * Abstract method all workers must implement, used be health checkers to check that
	 * everything is OK with this worker 
	 * 
	 * @return null of everything is OK, otherwise an descriptive error message of the problem.
	 */
	public abstract String isOK();
	
	/**
	 * Method all inheriting workers must implement. It responsible for writing the status for that specific
	 * type of worker in the CLI
	 */
    public abstract void displayStatus(int workerId, PrintStream out, boolean complete);
	 

    public static void printCert(X509Certificate cert, PrintStream out){
    	DateFormat df = DateFormat.getDateInstance();        
    	
    	out.println("DN : " + cert.getSubjectDN().toString());
    	out.println("SerialNumber : " + cert.getSerialNumber().toString(16));
    	out.println("Issuer DN : " + cert.getIssuerDN().toString());
    	out.println("Valid from :" +  df.format(cert.getNotBefore()));
    	out.println("Valid to : " +  df.format(cert.getNotAfter()));
    	out.println("\n\n");
    }
	
}
