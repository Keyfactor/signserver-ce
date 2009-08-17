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
import java.util.Date;
import java.util.Enumeration;

import org.signserver.common.CryptoTokenStatus;
import org.signserver.common.WorkerConfig;

/**
 * Class used to display the status of a GroupKeyService such as 
 * keys in database etc.
 * 
 * 
 * @author Philip Vendil
 * $Id$
 */
public class GroupKeyServiceStatus extends CryptoTokenStatus {

	private static final long serialVersionUID = 1L;
	
	private long numOfUnassignedKeys;	 
	private long numOfKeys;	 
	private long numOfAssignedKeys;	 

	private String currentEncKeyRef;
	private long currentEncKeyNumEncryptions;
	private Date currentEncKeyStartDate;
	
	public GroupKeyServiceStatus(int workerId, int tokenStatus, WorkerConfig config, long numOfUnassignedKeys,
			long numOfKeys, long numOfAssignedKeys, String currentEncKeyRef,
			long currentEncKeyNumEncryptions, Date currentEncKeyStartDate) {
		super(workerId, tokenStatus,config);
		this.numOfUnassignedKeys = numOfUnassignedKeys;
		this.numOfKeys = numOfKeys;
		this.numOfAssignedKeys = numOfAssignedKeys;
        this.currentEncKeyRef = currentEncKeyRef;
        this.currentEncKeyNumEncryptions = currentEncKeyNumEncryptions;
        this.currentEncKeyStartDate = currentEncKeyStartDate;
	}

	@Override
	public void displayStatus(int workerId, PrintStream out, boolean complete) {
		out.println("Status of Group Key Service with Id " + workerId + " is :\n" +
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

			out.println(" Total number of generated keys in database : " + numOfKeys);
			out.println(" Number of assigned keys in database : " + numOfAssignedKeys);
			out.println(" Number of unassigned keys in database : " + numOfUnassignedKeys);
			if(currentEncKeyRef != null){
				out.println("\n\n Currently used encryption key reference is : " + currentEncKeyRef);
				out.println(" Currently used encryption key count : " + currentEncKeyNumEncryptions);
				out.println(" Currently used encryption key start date : " + currentEncKeyStartDate.toString());
			}else{
				out.println("\n\n No encryption key have been initialized.");
			}
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


	public String getCurrentEncKeyRef() {
		return currentEncKeyRef;
	}

	/**
	 * @return the currentEncKeyNumEncryptions
	 */
	public long getCurrentEncKeyNumEncryptions() {
		return currentEncKeyNumEncryptions;
	}

	/**
	 * @return the currentEncKeyStartDate
	 */
	public Date getCurrentEncKeyStartDate() {
		return currentEncKeyStartDate;
	}



}
