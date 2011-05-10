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
import java.util.Enumeration;
import java.util.Iterator;

import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerConfig;


 

/**
 * removes a property for a given signer
 *
 * @version $Id$
 */
public class RemoveWorkerPropertyCommand extends BaseCommand {
	

    /**
     * Creates a new instance of SetPropertyCommand
     *
     * @param args command line arguments
     */
    public RemoveWorkerPropertyCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 2) {
	       throw new IllegalAdminCommandException("Usage: signserver <-host hostname (optional)> removeworker  <workerid | workerName> \n" + 
	       		                                  "Example 1 : signserver removeworker 1 \n" +
	                                              "Example 2 : signserver removeworker -host node3.someorg.com mySigner\n\n");		       
	    }	
        try {            
        	
        	
        	        	
        	String workerid = args[1];

        	if(workerid.substring(0, 1).matches("\\d")){            		
        		removeWorker(Integer.parseInt(workerid),  hostname);            		
        	}else{
        		// named worker is requested
        		int id = getCommonAdminInterface(hostname).getWorkerId(workerid.trim());
        		if(id == 0){
        			throw new IllegalAdminCommandException("Error: No worker with the given name could be found");
        		}
        		removeWorker(id,  hostname);        			
        	}    	

        	
    		this.getOutputStream().println("\n\n");
        	
        } catch (IllegalAdminCommandException e) {
        	throw e;  
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

    // execute
    
	public int getCommandType() {
		return TYPE_EXECUTEONMASTER;
	}
	
    private void removeGlobalProperties(int workerid, String hostname) throws RemoteException, Exception {
        GlobalConfiguration gc = getCommonAdminInterface(hostname).getGlobalConfiguration();
        Enumeration<String> en = gc.getKeyEnumeration();
        while(en.hasMoreElements()){
        	String key = en.nextElement();
        	if(key.toUpperCase().startsWith("GLOB.WORKER" + workerid)){
        		
        		key = key.substring("GLOB.".length());
        		if(getCommonAdminInterface(hostname).removeGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, key)){
        	  	  getOutputStream().println("  Global property '" + key + "' removed successfully.");
        		}else{
        		  getOutputStream().println("  Failed removing global property '" + key + "'.");
        		}
        	}
        }  	
	}
	
	private void removeWorker(int workerId, String hostname) throws RemoteException, Exception{
    	this.getOutputStream().println("Removing all properties related to worker with id " + workerId + "\n");
    	this.getOutputStream().println("Activate the removal with the reload command\n\n");
    	
    	removeGlobalProperties(workerId, hostname);
    	
    	WorkerConfig wc = getCommonAdminInterface(hostname).getCurrentWorkerConfig(workerId);
    	Iterator<Object> iter = wc.getProperties().keySet().iterator();
    	while(iter.hasNext()){
    		String key = (String) iter.next();
        	if(getCommonAdminInterface(hostname).removeWorkerProperty(workerId,key)){
        		this.getOutputStream().println("  Property '" + key + "' removed.");	
        	}else{
        		this.getOutputStream().println("  Error, the property '"+ key + "' couldn't be removed.");
        	}    	
    	}    	
	}
}
