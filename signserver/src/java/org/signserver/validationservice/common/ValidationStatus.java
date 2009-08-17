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
package org.signserver.validationservice.common;

import java.io.PrintStream;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;

import org.signserver.common.CryptoTokenStatus;
import org.signserver.common.WorkerConfig;

/**
 * Class used to display the status of a ValidationService such as 
 * if the connection to the underlying services are OK.
 * 
 * 
 * @author Philip Vendil
 * $Id$
 */
public class ValidationStatus extends CryptoTokenStatus {

	public static final String CONNECTION_OK     = "CONNECTION_OK";
	public static final String CONNECTION_FAILED = "CONNECTION_FAILED";
	
	private static final long serialVersionUID = 1L;
	
    private HashMap<Integer,String> validatorStatuses;
	
	public ValidationStatus(int workerId, int tokenStatus, WorkerConfig config, 
			HashMap<Integer,String> validatorStatuses) {
		super(workerId, tokenStatus,config);
		this.validatorStatuses = validatorStatuses;
	}

	@Override
	public void displayStatus(int workerId, PrintStream out, boolean complete) {
		out.println("Status of Validation Service with Id " + workerId + " is :\n" +
				"  SignToken Status : "+signTokenStatuses[getTokenStatus()] + " \n\n" );

		if(complete){    	
			out.println("Active Properties are :");


			if(getActiveSignerConfig().getProperties().size() == 0){
				out.println("  No properties exists in active configuration\n");
			}

			Enumeration<?> propertyKeys = getActiveSignerConfig().getProperties().keys();
			while(propertyKeys.hasMoreElements()){
				String key = (String) propertyKeys.nextElement();
				out.println("  " + key + "=" + getActiveSignerConfig().getProperties().getProperty(key) + "\n");
			}        		

			out.println("\n");

			out.println(" Total number of validators : " + validatorStatuses.size() + "\n");
			for (Iterator<Integer> iterator = validatorStatuses.keySet().iterator(); iterator.hasNext();) {
				Integer validatorId = iterator.next();
				if(validatorStatuses.get(validatorId).equals(CONNECTION_OK)){
					out.println(" Status validator " + validatorId + " : OK");
				}else{
					out.println(" Status validator " + validatorId + " : FAILED");
				}
				
			}
		}		
		
	}



}
