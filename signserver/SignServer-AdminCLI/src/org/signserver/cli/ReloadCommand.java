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
 


/**
 * Reloads the current configuration
 *
 * @version $Id$
 */
public class ReloadCommand extends BaseCommand {
    /**
     * Creates a new instance of ReloadCommand
     *
     * @param args command line arguments
     */
    public ReloadCommand(String[] args) {
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
	       throw new IllegalAdminCommandException("Usage: signserver reload <worker id or name | all> \n\n"+
	    		                                  "Example 1 : signserver reload all \n" +
	    		                                  "Example 2 : signserver reload myWorker \n" +
	    		                                  "Example 1 : signserver reload 1 \n");
	       
	    }	
        try {            
        	int workerId = 0;
        	
        	if(!args[1].equalsIgnoreCase("all")){        	  
        		workerId = getWorkerId(args[1], hostname);
        		if(workerId == 0){
        			throw new IllegalAdminCommandException("Error: Worker Id cannot be 0.");
        		}
          	}  
        	
            this.getCommonAdminInterface(hostname).reloadConfiguration(workerId);
        	
        	this.getOutputStream().println("SignServer reloaded successfully\n");
        	this.getOutputStream().println("Current configuration is now activated.\n");
        	
        	
        } catch (IllegalAdminCommandException e) {
        	throw e;  
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

	public int getCommandType() {
		return TYPE_EXECUTEONALLNODES;
	}

    // execute
}
