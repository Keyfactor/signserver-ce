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
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerStatus;



/**
 * Gets the current status of the given worker
 *
 * @version $Id$
 */
public class GetStatusCommand extends BaseCommand {
	
	
	
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
    @SuppressWarnings("unchecked")
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
        	        	
    		this.getOutputStream().println("Current version of server is : " + getCommonAdminInterface(hostname).getGlobalConfiguration().getAppVersion() + "\n\n");
        	
        	if(allSigners){
        		if(complete){
        		  displayGlobalConfiguration(hostname);
        		}
        		
        		List workers = null;
        		if(CommonAdminInterface.isSignServerMode()){
        		  workers = getCommonAdminInterface(hostname).getWorkers(GlobalConfiguration.WORKERTYPE_PROCESSABLE);
        		}else{
        			workers = getCommonAdminInterface(hostname).getWorkers(GlobalConfiguration.WORKERTYPE_MAILSIGNERS);
        		}
        		Collections.sort(workers);
        		
        		Iterator<?> iter = workers.iterator();
        		while(iter.hasNext()){
        			Integer id = (Integer) iter.next();        			
        			displayWorkerStatus(id.intValue(),getCommonAdminInterface(hostname).getStatus(id.intValue()), complete);
        		}
        		
        	}else{
        		int id = getWorkerId(args[2], hostname);
        		displayWorkerStatus(id, getCommonAdminInterface(hostname).getStatus(id), complete);
        	}


        }catch (Exception e) {
        	if(e instanceof IllegalAdminCommandException){
        		throw (IllegalAdminCommandException) e;
        	}
        	throw new ErrorAdminCommandException(e);            
        }
    }

    private void displayWorkerStatus(int workerid, WorkerStatus status, boolean complete) {
		status.displayStatus(workerid, getOutputStream(), complete);
	}
    


	private void displayGlobalConfiguration(String hostname) throws RemoteException, Exception {
		GlobalConfiguration gc = getCommonAdminInterface(hostname).getGlobalConfiguration();
		this.getOutputStream().println("The Global Configuration of Properties are :\n" );
								
		if(!gc.getKeyEnumeration().hasMoreElements()){
			this.getOutputStream().println("  No properties exists in global configuration\n");
		}

		Enumeration<String> propertyKeys = gc.getKeyEnumeration();
		while(propertyKeys.hasMoreElements()){
			String key = (String) propertyKeys.nextElement();
			this.getOutputStream().println("  " + key + "=" + gc.getProperty(key) + "\n");
		}        		

		if(gc.getState().equals(GlobalConfiguration.STATE_INSYNC)){
			this.getOutputStream().println("  The global configuration is in sync with the database.\n");
		}else{
			this.getOutputStream().println("  WARNING: The global configuratuon is out of sync with the database.\n");
		}
		
		this.getOutputStream().println("\n");
		
	}

	// execute
	public int getCommandType() {
		return TYPE_EXECUTEONALLNODES;
	}
}
