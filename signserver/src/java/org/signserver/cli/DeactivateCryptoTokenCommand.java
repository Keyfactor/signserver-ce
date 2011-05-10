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
 * Command used to deactivate a Crypto Token
 *
 * @version $Id$
 */
public class DeactivateCryptoTokenCommand extends BaseCommand {
	protected static final int HELP = 0;
	protected static final int TRYING = 1;
	protected static final int SUCCESS = 2;
	
    /**
     * Creates a new instance of DeactivateSignTokenCommand
     *
     * @param args command line arguments
     */
    public DeactivateCryptoTokenCommand(String[] args) {
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
        	
        	int workerid = getWorkerId(args[1], hostname);
        	checkThatWorkerIsProcessable(workerid,hostname);
        	        	
        	
        	this.getOutputStream().println(resources[TRYING] + workerid + "\n");
        	this.getCommonAdminInterface(hostname).deactivateSigner(workerid);        			                
        	this.getOutputStream().println(resources[SUCCESS]);

        } catch( IllegalAdminCommandException e ) {
            throw e;
        } catch( ErrorAdminCommandException e ) {
            throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }  
    }
    
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
    	String[] resources =  {"Usage: signserver deactivatecryptotoken <worker id | worker name> \n" + 
                               "Example: signserver deactivatecryptotoken 1 \n"+
                               "Example 2 : signserver deactivatecryptotoken mySigner \n\n",
                               "Trying to deactivate crypto token of worker with id : ",
                               "Deactivation of worker was successful\n\n"};
        execute(hostname,resources);   
    }

	public int getCommandType() {
		return TYPE_EXECUTEONALLNODES;
	}

    // execute
}
