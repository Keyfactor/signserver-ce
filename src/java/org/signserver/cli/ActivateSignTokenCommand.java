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

import org.signserver.common.SignerStatus;



/**
 * Command used to activate a Sign Token
 *
 * @version $Id: ActivateSignTokenCommand.java,v 1.1 2007-02-27 16:18:08 herrvendil Exp $
 */
public class ActivateSignTokenCommand extends BaseCommand {
	
	
    /**
     * Creates a new instance of ActivateSignTokenCommand
     *
     * @param args command line arguments
     */
    public ActivateSignTokenCommand(String[] args) {
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
	       throw new IllegalAdminCommandException("Usage: signserver activatesigntoken <signerid | signerName> <authentication code> \n" + 
	       		                                  "Example 1 : signserver activatesigntoken 1 123456 \n\n" +
	    		                                  "Example 2 : signserver activatesigntoken mySigner 123456 \n\n");	       
	    }	
        try {            
        	
        	int signerid = getWorkerId(args[1], hostname);
        	checkThatWorkerIsSigner(signerid,hostname);
        	String authCode = args[2];
        	        	
        	
        	this.getOutputStream().println("Trying to activate sign token of signer with id : " + signerid + "\n");
        	this.getSignSession(hostname).activateSigner(signerid, authCode);
        	
        	if(((SignerStatus) getSignSession(hostname).getStatus(signerid)).getTokenStatus() == SignerStatus.STATUS_ACTIVE){
        		this.getOutputStream().println("Activation of signer was successful\n\n");
        	}else{
        		this.getOutputStream().println("Activation of signer FAILED\n\n");
        	}
        	
        	  
        	
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

	public int getCommandType() {
		return TYPE_EXECUTEONALLNODES;
	}

    // execute
}
