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

import org.ejbca.ui.cli.util.ConsolePasswordReader;
import org.signserver.common.MailSignerStatus;
import org.signserver.common.SignerStatus;



/**
 * Command used to activate a Crypto Token
 *
 * @version $Id$
 */
public class ActivateCryptoTokenCommand extends BaseCommand {
	
	protected static final int HELP = 0;
	protected static final int TRYING = 1;
	protected static final int SUCCESS = 2;
	protected static final int FAIL = 3;
	
    /**
     * Creates a new instance of ActivateSignTokenCommand
     *
     * @param args command line arguments
     */
    public ActivateCryptoTokenCommand(String[] args) {
        super(args);
    }    
    
    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    protected void execute(String hostname,String[] resources) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 2) {
	       throw new IllegalAdminCommandException(resources[HELP]);	       
	    }	
        try {            
        	
        	int workerid = getWorkerId(args[1], hostname);
        	checkThatWorkerIsProcessable(workerid,hostname);
        	String authCode = null;
            if (args.length > 2) {
            	authCode = args[2];
            } else {
                getOutputStream().print("Enter authorization code: ");
                // Read the password, but mask it so we don't display it on the console
                ConsolePasswordReader r = new ConsolePasswordReader();
                authCode = String.valueOf(r.readPassword());            	
            }
        	
        	this.getOutputStream().println( resources[TRYING]+ workerid + "\n");
        	this.getCommonAdminInterface(hostname).activateSigner(workerid, authCode);
        	
        	boolean active = false;
        	if(CommonAdminInterface.isSignServerMode()){
        		active = ((SignerStatus) getCommonAdminInterface(hostname).getStatus(workerid)).getTokenStatus() == SignerStatus.STATUS_ACTIVE;
        	}
        	if(CommonAdminInterface.isMailSignerMode()){
        		active = ((MailSignerStatus) getCommonAdminInterface(hostname).getStatus(workerid)).getTokenStatus() == SignerStatus.STATUS_ACTIVE;
        	}
        	if(active){
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
    	String[] resources =  {"Usage: signserver activatesigntoken <worker id | worker name> <authentication code> \n" + 
    			               "Leaving out authorization code will prompt for it.\n\n" +                               
    			               "Example 1 : signserver activatecryptotoken 1 123456 \n" +
                               "Example 2 : signserver activatecryptotoken 1 \n" +
                               "Example 3 : signserver activatecryptotoken mySigner 123456 \n\n",
                               "Trying to activate crypto token of worker with id : ",
                               "Activation of worker was successful\n\n",
                               "Activation of worker FAILED\n\n"};
        execute(hostname,resources);   
    }
    

	public int getCommandType() {
		return TYPE_EXECUTEONALLNODES;
	}

    // execute
}
