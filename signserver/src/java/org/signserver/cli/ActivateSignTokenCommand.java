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
 * @version $Id: ActivateSignTokenCommand.java,v 1.3 2007-03-14 20:38:32 primelars Exp $
 */
public class ActivateSignTokenCommand extends BaseCommand {
	
	protected static final int HELP = 0;
	protected static final int TRYING = 1;
	protected static final int SUCCESS = 2;
	protected static final int FAIL = 3;
	
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
    protected void execute(String hostname,String[] resources) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 3) {
	       throw new IllegalAdminCommandException(resources[HELP]);	       
	    }	
        try {            
        	
        	int signerid = getWorkerId(args[1], hostname);
        	checkThatWorkerIsSigner(signerid,hostname);
        	String authCode = args[2];
        	        	
        	
        	this.getOutputStream().println( resources[TRYING]+ signerid + "\n");
        	this.getSignSession(hostname).activateSigner(signerid, authCode);
        	
        	if(((SignerStatus) getSignSession(hostname).getStatus(signerid)).getTokenStatus() == SignerStatus.STATUS_ACTIVE){
        		this.getOutputStream().println(resources[SUCCESS]);
        	}else{
        		this.getOutputStream().println(resources[FAIL]);
        	}
        } catch( IllegalAdminCommandException e ) {
            throw e;
        } catch( ErrorAdminCommandException e ) {
            throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }  
    }
    
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
    	String[] resources =  {"Usage: signserver activatesigntoken <signerid | signerName> <authentication code> \n" + 
                               "Example 1 : signserver activatesigntoken 1 123456 \n\n" +
                               "Example 2 : signserver activatesigntoken mySigner 123456 \n\n",
                               "Trying to activate sign token of signer with id : ",
                               "Activation of signer was successful\n\n",
                               "Activation of signer FAILED\n\n"};
        execute(hostname,resources);   
    }
    

	public int getCommandType() {
		return TYPE_EXECUTEONALLNODES;
	}

    // execute
}
