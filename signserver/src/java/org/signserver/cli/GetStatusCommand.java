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

package org.signserver.cli;

import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import org.signserver.common.AuthorizedClient;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ServiceStatus;
import org.signserver.common.SignerConfig;
import org.signserver.common.SignerStatus;
import org.signserver.common.WorkerStatus;



/**
 * Gets the current status of the given worker
 *
 * @version $Id: GetStatusCommand.java,v 1.3 2007-03-16 11:07:52 herrvendil Exp $
 */
public class GetStatusCommand extends BaseCommand {
	
	
	private static final String[] signTokenStatuses = {"", "Active", "Offline"};
    /**
     * Creates a new instance of GetStatusCommand
     *
     * @param args command line arguments
     */
    public GetStatusCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
    	String errormessage = "Usage: signserver getstatus <complete | brief> <workerId | workerName | all> \n" +
    	                      "Example 1 : signserver getstatus complete all \n" +
                              "Example 2 : signserver getstatus brief 1 \n" +
    	                      "Example 3 : signserver getstatus complete mySigner \n\n";
    	
    	
        if (args.length  != 3 ) {
	       throw new IllegalAdminCommandException(errormessage);	       
	    }	
        try {            
        	
        	String mode = args[1];
        	
        	boolean allSigners = false;
        	if(args[2].equalsIgnoreCase("all")){        	  
        	  allSigners = true;
        	}        	
        	        
        	if(!(mode.equalsIgnoreCase("complete") || mode.equalsIgnoreCase("brief"))){
        		throw new IllegalAdminCommandException(errormessage);	
        	}
        	
        	boolean complete = mode.equalsIgnoreCase("complete");
        	        	
    		this.getOutputStream().println("Current version of server is : " + getGlobalConfigurationSession(hostname).getGlobalConfiguration().getAppVersion() + "\n\n");
        	
        	if(allSigners){
        		if(complete){
        		  displayGlobalConfiguration(hostname);
        		}
        		List workers = getGlobalConfigurationSession(hostname).getWorkers(GlobalConfiguration.WORKERTYPE_SIGNERS);
        		Collections.sort(workers);
        		
        		Iterator iter = workers.iterator();
        		while(iter.hasNext()){
        			Integer id = (Integer) iter.next();        			
        			displayWorkerStatus(id.intValue(),getSignSession(hostname).getStatus(id.intValue()), complete);
        		}
        		
        	}else{
        		int id = getWorkerId(args[2], hostname);
        		displayWorkerStatus(id, getSignSession(hostname).getStatus(id), complete);
        	}


        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

    private void displayWorkerStatus(int workerid, WorkerStatus status, boolean complete) {
		if(status instanceof SignerStatus){
			displaySignerStatus(workerid,(SignerStatus) status,complete);
		}
		if(status instanceof ServiceStatus){
			displayServiceStatus(workerid,(ServiceStatus) status,complete);
		}
	}
    
    private void displayServiceStatus(int serviceid, ServiceStatus status, boolean complete) {

    	this.getOutputStream().println("Status of Service with Id " + serviceid + " is :\n");
    	this.getOutputStream().println("  Service was last run at : " + status.getLastRunDate() +"\n");    	    	
    	
    	if(complete){    	
    		this.getOutputStream().println("Active Properties are :");


    		if(status.getActiveSignerConfig().getProperties().size() == 0){
    			this.getOutputStream().println("  No properties exists in active configuration\n");
    		}

    		Enumeration propertyKeys = status.getActiveSignerConfig().getProperties().keys();
    		while(propertyKeys.hasMoreElements()){
    			String key = (String) propertyKeys.nextElement();
    			this.getOutputStream().println("  " + key + "=" + status.getActiveSignerConfig().getProperties().getProperty(key) + "\n");
    		}        		

    		this.getOutputStream().println("\n");

    	}
		
	}

	private void displaySignerStatus(int signerid, SignerStatus status, boolean complete){

    	this.getOutputStream().println("Status of Signer with Id " + signerid + " is :\n" +
    			                       "  SignToken Status : "+signTokenStatuses[status.getTokenStatus()] + " \n\n" );
    	
    	if(complete){    	
    		this.getOutputStream().println("Active Properties are :");
    		
    		
    		if(status.getActiveSignerConfig().getProperties().size() == 0){
    			this.getOutputStream().println("  No properties exists in active configuration\n");
    		}
    		
    		Enumeration propertyKeys = status.getActiveSignerConfig().getProperties().keys();
    		while(propertyKeys.hasMoreElements()){
    			String key = (String) propertyKeys.nextElement();
    			this.getOutputStream().println("  " + key + "=" + status.getActiveSignerConfig().getProperties().getProperty(key) + "\n");
    		}        		
    		
    		this.getOutputStream().println("\n");
    		
    		this.getOutputStream().println("Active Authorized Clients are are (Cert DN, IssuerDN):");
           	Iterator iter =  new SignerConfig(status.getActiveSignerConfig()).getAuthorizedClients().iterator();
        	while(iter.hasNext()){
        		AuthorizedClient client = (AuthorizedClient) iter.next();
        		this.getOutputStream().println("  " + client.getCertSN() + ", " + client.getIssuerDN() + "\n");
        	}
        	if(status.getSignerCertificate() == null){
          	  this.getOutputStream().println("Error: No Signer Certificate have been uploaded to this signer.\n");	
          	}else{
          	  this.getOutputStream().println("The current configuration use the following signer certificate : \n");
                printCert((X509Certificate) status.getSignerCertificate() );
          	}
    	}
    }

	private void displayGlobalConfiguration(String hostname) throws RemoteException, Exception {
		GlobalConfiguration gc = getGlobalConfigurationSession(hostname).getGlobalConfiguration();
		this.getOutputStream().println("The Global Configuration of Properties are :\n" );
						
		if(!gc.getKeyIterator().hasNext()){
			this.getOutputStream().println("  No properties exists in global configuration\n");
		}

		Iterator propertyKeys = gc.getKeyIterator();
		while(propertyKeys.hasNext()){
			String key = (String) propertyKeys.next();
			this.getOutputStream().println("  " + key + "=" + gc.getProperty(key) + "\n");
		}        		

		this.getOutputStream().println("\n");
		
	}

	// execute
	public int getCommandType() {
		return TYPE_EXECUTEONALLNODES;
	}
}
