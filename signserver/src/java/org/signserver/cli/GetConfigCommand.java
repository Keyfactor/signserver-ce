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
import org.signserver.common.SignerConfig;
import org.signserver.common.WorkerConfig;



/**
 * Gets the current configuration of the given signer, this might not be the same as
 * the active configuration.
 *
 * @version $Id: GetConfigCommand.java,v 1.1 2007-02-27 16:18:08 herrvendil Exp $
 */
public class GetConfigCommand extends BaseCommand {
	
	
    /**
     * Creates a new instance of GetConfigCommand
     *
     * @param args command line arguments
     */
    public GetConfigCommand(String[] args) {
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
	       throw new IllegalAdminCommandException("Usage: signserver getconfig <workerid | workerName | global> \n" + 
	       		                                  "Example 1 : signserver getconfig 1 \n" + 
	                                              "Example 2 : signserver getconfig mySigner \n" +
	                                              "Example 3 : signserver getconfig global \n\n");
	    }	
        try {            
        	
        	String workerid = args[1];
        	
        	if(workerid.substring(0, 1).matches("\\d")){
        		displayWorkerConfig(Integer.parseInt(workerid),  hostname);
        		
        	}else{
        		if(workerid.trim().equalsIgnoreCase("GLOBAL")){
        			// global configuration is requested
        			displayGlobalConfiguration(hostname);
        			
        		}else{
        			// named worker is requested
        			int id = getSignSession(hostname).getSignerName(workerid);
            		if(id == 0){
            			throw new IllegalAdminCommandException("Error: No worker with the given name could be found");
            		}
        			displayWorkerConfig(id,  hostname);        			
        		}
        	}
 
        	
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

	private void displayGlobalConfiguration(String hostname) throws RemoteException, Exception {
		GlobalConfiguration gc = getGlobalConfigurationSession(hostname).getGlobalConfiguration();
		Iterator iter = gc.getKeyIterator();
		this.getOutputStream().println(" This node " + hostname + " have the following Global Configuration:");
		while(iter.hasNext()){
			String key = (String) iter.next();
			this.getOutputStream().println("   Key : " + key + " Value : " + gc.getProperty(key));
		}
	}

	public int getCommandType() {
		return TYPE_EXECUTEONMASTER;
	}
	
	private void displayWorkerConfig(int workerId, String hostname) throws RemoteException, Exception{
       	WorkerConfig config = this.getSignSession(hostname).getCurrentSignerConfig(workerId);
    	
    	boolean isSigner = config instanceof SignerConfig;
    	        	
    	this.getOutputStream().println(
    			                       "OBSERVE that this command displays the current configuration which\n"+
    			                       "doesn't have to be the same as the active configuration.\n" +
    			                       "Configurations are activated with the reload command. \n\n" +
    			                       "The current configuration of worker with id : " + workerId + " is :");
    	
    	if(isSigner){
    		this.getOutputStream().println("  This is a configuration for a Signer.\n\n");
    	}else{
    		this.getOutputStream().println("  This is a configuration for a Service.\n\n");
    	}
    	
    	if(config.getProperties().size() == 0){
    		this.getOutputStream().println("  No properties exists in the current configuration\n");
    	}
    	
    	Enumeration propertyKeys = config.getProperties().keys();
    	while(propertyKeys.hasMoreElements()){
    		String key = (String) propertyKeys.nextElement();
    		this.getOutputStream().println("  " + key + "=" + config.getProperties().getProperty(key) + "\n");
    	}
    	
    	
    	if(isSigner){
    		if(((SignerConfig) config).getSignerCertificate() == null){
    			this.getOutputStream().println(" No Signer Certificate have been uploaded to this signer.\n");	
    		}else{
    			this.getOutputStream().println("The current configuration use the following signer certificate : \n");
    			printCert(((SignerConfig) config).getSignerCertificate());
    		}  
    	}
	}
	
    // execute
}
