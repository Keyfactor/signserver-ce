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

import org.signserver.common.ProcessableConfig;
import org.signserver.common.WorkerConfig;


/**
 * Gets the current configurations list of authorized clients
 *
 * @version $Id$
 */
public class ListAuthorizedClientsCommand extends BaseCommand {
	
	
    /**
     * Creates a new instance of ListAuthorizedClientsCommand
     *
     * @param args command line arguments
     */
    public ListAuthorizedClientsCommand(String[] args) {
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
	       throw new IllegalAdminCommandException("Usage: signserver listauthorizedclients <signerid> \n" + 
	       		                                  "Example: signserver listauthorizedclients 1 \n\n");	       
	    }	
        try {            
        	
        	int signerid = getWorkerId(args[1], hostname);
        	checkThatWorkerIsProcessable(signerid,hostname);
        	
        	WorkerConfig config = this.getCommonAdminInterface(hostname).getCurrentWorkerConfig(signerid);
        	
        	this.getOutputStream().println(
         			                       "OBSERVE that this command displays the current configuration which\n"+
        			                       "doesn't have to be the same as the active configuration.\n" +
        			                       "Configurations are activated with the reload command. \n\n" +
        			                       "The current list of authorized clients to " + signerid + " are :\n");
        	
        	if(new ProcessableConfig(config).getAuthorizedClients().size() == 0){
        		this.getOutputStream().println("  No authorized clients exists-\n");
        	}
        	
        	printAuthorizedClients(config);
        	

    		this.getOutputStream().println("\n\n");
        	
        } catch (IllegalAdminCommandException e) {
        	throw e;  
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }
    
	public int getCommandType() {
		return TYPE_EXECUTEONMASTER;
	}

    // execute
}
