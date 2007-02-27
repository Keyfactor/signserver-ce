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
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Common base class used to report the status of a signer or service. Should
 * be inherited by all workers.
 * 
 * @author Philip Vendil
 *
 * $Id: WorkerStatus.java,v 1.1 2007-02-27 16:18:10 herrvendil Exp $
 */

public class WorkerStatus implements Serializable{

	
	private static final long serialVersionUID = 1L;

	protected String hostname = null;
	protected WorkerConfig activeconfig= null;	

	
	/** 
	 * Main constuctor
	 */
	public WorkerStatus(WorkerConfig config){	
	    try {
	    	hostname= InetAddress.getLocalHost().getHostName();
	    } catch (UnknownHostException e) {
	    	hostname= "unknown";
	    }
	    activeconfig = config;
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
	

	 

		
	
}
