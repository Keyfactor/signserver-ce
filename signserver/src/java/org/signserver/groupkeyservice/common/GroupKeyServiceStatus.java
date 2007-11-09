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
package org.signserver.groupkeyservice.common;

import java.io.PrintStream;
import java.util.Enumeration;

import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;

/**
 * Class used to display the status of a GroupKeyService such as 
 * keys in database etc.
 * 
 * 
 * @author Philip Vendil
 * $Id: GroupKeyServiceStatus.java,v 1.1 2007-11-09 15:46:45 herrvendil Exp $
 */
public class GroupKeyServiceStatus extends WorkerStatus {

	private static final long serialVersionUID = 1L;
	
	private long numOfUnassignedKeys;	 
	private long numOfKeys;	 
	private long numOfAssignedKeys;	 
	private long numByCreationDate;	 
	private long numByFirstUsedDate;	 
	private long numByLastFetchedDate;
	private long currentEncKeyIndex;
	private int tokenStatus = 0;
	
	public GroupKeyServiceStatus(int tokenStatus, WorkerConfig config, long numOfUnassignedKeys,
			long numOfKeys, long numOfAssignedKeys, long numByCreationDate,
			long numByFirstUsedDate, long numByLastFetchedDate, long currentEncKeyIndex) {
		super(config);
		this.tokenStatus = tokenStatus;
		this.numOfUnassignedKeys = numOfUnassignedKeys;
		this.numOfKeys = numOfKeys;
		this.numOfAssignedKeys = numOfAssignedKeys;
		this.numByCreationDate = numByCreationDate;
		this.numByFirstUsedDate = numByFirstUsedDate;
		this.numByLastFetchedDate = numByLastFetchedDate;
		this.currentEncKeyIndex = currentEncKeyIndex;
	}
	
	/**
	 * @return Returns the tokenStatus.
	 */
	public int getTokenStatus() {
		return tokenStatus;
	}
	

	@Override
	public void displayStatus(int workerId, PrintStream out, boolean complete) {
		out.println("Status of Signer with Id " + workerId + " is :\n" +
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

			out.println("TODO");
		}		
		
	}

	public long getNumOfUnassignedKeys() {
		return numOfUnassignedKeys;
	}

	public long getNumOfKeys() {
		return numOfKeys;
	}

	public long getNumOfAssignedKeys() {
		return numOfAssignedKeys;
	}

	public long getNumByCreationDate() {
		return numByCreationDate;
	}

	public long getNumByFirstUsedDate() {
		return numByFirstUsedDate;
	}

	public long getNumByLastFetchedDate() {
		return numByLastFetchedDate;
	}

	public long getCurrentEncKeyIndex() {
		return currentEncKeyIndex;
	}



}
