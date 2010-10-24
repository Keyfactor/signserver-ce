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

import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ResyncException;
 


/**
 * Reloads the current configuration
 *
 * @version $Id$
 */
public class ResyncCommand extends BaseCommand {
    /**
     * Creates a new instance of ReloadCommand
     *
     * @param args command line arguments
     */
    public ResyncCommand(String[] args) {
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
	       throw new IllegalAdminCommandException("Usage: signserver resync <sure> \n\n"+
	    		                                  "Example 1 : signserver resync true \n" +
	    		                                  "Example 2 : signserver resync yes \n" +
	    		                                  "This command resyncronizes a out-of-sync Global Configuration.\n"+
	    		                                  "Warning: Only use this commando if you know what you are doing.");
	       
	    }	
        try {            
        	
        	
        	if(args[1].equalsIgnoreCase("true") || args[1].equalsIgnoreCase("yes")){        	  
        		this.getOutputStream().println("Resyncronizing database...");
            	try{
            		if(this.getCommonAdminInterface(hostname).getGlobalConfiguration().getState().equals(GlobalConfiguration.STATE_OUTOFSYNC)){
                      this.getCommonAdminInterface(hostname).resync();
                      this.getOutputStream().println("Syncronization was successful\n");        	
            		}else{
            		  this.getOutputStream().println("Global configuration is not out of sync. Operation aborted.\n");
            		}
              	}catch(ResyncException e){
              		this.getOutputStream().println("Syncronization failed: " + e.getMessage());
              	}
          	}else{
          		this.getOutputStream().println("Syncronization aborted.");
          	}        	
        	
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
