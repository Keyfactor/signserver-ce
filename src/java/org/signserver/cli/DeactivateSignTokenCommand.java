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
 * Command used to deactivate a Sign Token
 *
 * @version $Id: DeactivateSignTokenCommand.java,v 1.1 2007-02-27 16:18:08 herrvendil Exp $
 */
public class DeactivateSignTokenCommand extends BaseCommand {
	
	
    /**
     * Creates a new instance of DeactivateSignTokenCommand
     *
     * @param args command line arguments
     */
    public DeactivateSignTokenCommand(String[] args) {
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
	       throw new IllegalAdminCommandException("Usage: signserver deactivatesigntoken <signerid> \n" + 
	       		                                  "Example: signserver activatesigntoken 1 \n\n");	       
	    }	
        try {            
        	
        	int signerid = getWorkerId(args[1], hostname);
        	checkThatWorkerIsSigner(signerid,hostname);
        	        	
        	
        	this.getOutputStream().println("Trying to activate sign token of signer with id : " + signerid + "\n");
        	this.getSignSession(hostname).deactivateSigner(signerid);        			                
        	this.getOutputStream().println("Deactivation of signer was successful\n\n");
        	  
        	
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

	public int getCommandType() {
		return TYPE_EXECUTEONALLNODES;
	}

    // execute
}
