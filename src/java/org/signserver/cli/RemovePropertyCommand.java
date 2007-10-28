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

import org.signserver.common.GlobalConfiguration;

 

/**
 * removes a property for a given signer
 *
 * @version $Id: RemovePropertyCommand.java,v 1.3 2007-10-28 12:23:55 herrvendil Exp $
 */
public class RemovePropertyCommand extends BaseCommand {
	

    /**
     * Creates a new instance of SetPropertyCommand
     *
     * @param args command line arguments
     */
    public RemovePropertyCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 3) {
	       throw new IllegalAdminCommandException("Usage: signserver <-host hostname (optional)> removeproperty  <signerid | signerName | global | node> <propertykey>\n" + 
	       		                                  "Example 1 : signserver removeproperty 1 defaultKey\n" +
	                                              "Example 2 : signserver removeproperty -host node3.someorg.com mySigner defaultKey\n\n");		       
	    }	
        try {            
        	
        	
        	String propertykey = args[2];
        	        	
        	String workerid = args[1];

        	if(workerid.substring(0, 1).matches("\\d")){            		
        		removeWorkerProperty(Integer.parseInt(workerid),  hostname, propertykey);            		
        	}else{
        		if(workerid.trim().equalsIgnoreCase("GLOBAL")){
        			removeGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,hostname,propertykey);            			
        		}else{
        			if(workerid.trim().equalsIgnoreCase("NODE")){
        				removeGlobalProperty(GlobalConfiguration.SCOPE_NODE,hostname,propertykey);

        			}else{
        				// named worker is requested
        				int id = getCommonAdminInterface(hostname).getSignerId(workerid);
                		if(id == 0){
                			throw new IllegalAdminCommandException("Error: No worker with the given name could be found");
                		}
        				removeWorkerProperty(id,  hostname, propertykey);        			
        			}

        		}
        	}    	

        	
    		this.getOutputStream().println("\n\n");
        	
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

    // execute
    
	public int getCommandType() {
		return TYPE_EXECUTEONMASTER;
	}
	
    private void removeGlobalProperty(String scope, String hostname, String key) throws RemoteException, Exception {
    	this.getOutputStream().println("removing the global property " + key + " with scope " + scope + "\n");
    	this.getOutputStream().println("See current configuration with the getconfig command, activate it with the reload command");
    
    	getCommonAdminInterface(hostname).removeGlobalProperty(scope, key);
		
	}
	
	private void removeWorkerProperty(int workerId, String hostname, String propertykey) throws RemoteException, Exception{
    	this.getOutputStream().println("Removing the property " + propertykey + " from worker " + workerId + "\n");
    	this.getOutputStream().println("See current configuration with the getconfig command, activate it with the reload command\n\n");
    	if(getCommonAdminInterface(hostname).removeWorkerProperty(workerId,propertykey)){
    		this.getOutputStream().println("  Property Removed\n");	
    	}else{
    		this.getOutputStream().println("  Error, the property "+ propertykey + " doesn't seem to exist\n");
    	}
	}
}
