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

import java.text.DateFormat;
import java.util.Date;


/**
 * Class used when responding to the SignSession.getStatus() method, represents
 * the status of a specific service
 * @author Philip Vendil
 *
 * $Id: ServiceStatus.java,v 1.2 2007-03-05 06:48:32 herrvendil Exp $
 */

public class ServiceStatus extends WorkerStatus{

	private static final long serialVersionUID = 1L;

	
	/** 
	 * Main constuctor
	 */
	public ServiceStatus(ServiceConfig config){
		super(config.getWorkerConfig());

	}

	/**
	 * 
	 * @return returning the date this service was last run
	 */
	public String getLastRunDate(){
		Date lastRun = new ServiceConfig(activeconfig).getLastRunTimestamp();
		
		if(lastRun == null){
			return "Service doesn't seem to have been runned since start or reload of the server.";
		}
				
		return DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(lastRun);		
	}

		
	
}
