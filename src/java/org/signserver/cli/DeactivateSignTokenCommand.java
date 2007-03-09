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
 * @version $Id: DeactivateSignTokenCommand.java,v 1.2 2007-03-09 11:26:38 herrvendil Exp $
 */
public class DeactivateSignTokenCommand extends BaseCommand {
	protected static final int HELP = 0;
	protected static final int TRYING = 1;
	protected static final int SUCCESS = 2;
	
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
    public void execute(String hostname, String[] resources) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 2) {
	       throw new IllegalAdminCommandException(resources[HELP]);	       
	    }	
        try {            
        	
        	int signerid = getWorkerId(args[1], hostname);
        	checkThatWorkerIsSigner(signerid,hostname);
        	        	
        	
        	this.getOutputStream().println(resources[TRYING] + signerid + "\n");
        	this.getSignSession(hostname).deactivateSigner(signerid);        			                
        	this.getOutputStream().println(resources[SUCCESS]);
        	  
        	
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }
    
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
    	String[] resources =  {"Usage: signserver deactivatesigntoken <signerid> \n" + 
                               "Example: signserver deactivatesigntoken 1 \n"+
                               "Example 2 : signserver deactivatesigntoken mySigner \n\n",
                               "Trying to deactivate sign token of signer with id : ",
                               "Deactivation of signer was successful\n\n"};
        execute(hostname,resources);   
    }

	public int getCommandType() {
		return TYPE_EXECUTEONALLNODES;
	}

    // execute
}
