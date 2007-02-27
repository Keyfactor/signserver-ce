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
 * @version $Id: ReloadCommand.java,v 1.1 2007-02-27 16:18:09 herrvendil Exp $
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
        if (args.length != 1) {
	       throw new IllegalAdminCommandException("Usage: signserver reload  \n\n"  );	       
	    }	
        try {            
        	
            this.getSignSession(hostname).reloadConfiguration();
        	
        	this.getOutputStream().println("SignServer reloaded successfully\n");
        	this.getOutputStream().println("Current configuration is now activated.\n");
        	
        	
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

	public int getCommandType() {
		return TYPE_EXECUTEONALLNODES;
	}

    // execute
}
