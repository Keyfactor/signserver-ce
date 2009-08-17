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

import java.math.BigInteger;

import org.signserver.common.AuthorizedClient;

 


/**
 * removes an authorized client from a given signer
 *
 * @version $Id$
 */
public class RemoveAuthorizedClientCommand extends BaseCommand {
	

    /**
     * Creates a new instance of RemoveAuthorizedClientCommand
     *
     * @param args command line arguments
     */
    public RemoveAuthorizedClientCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 4) {
	       throw new IllegalAdminCommandException("Usage: signserver removeauthorizedclient <signerid> <certificatesn (hex)> <issuerd>\n" + 
	       		                                  "Example: signserver removeauthorizedclient 1 EF34242D232 \"CN=Test Root CA\"\n\n");	       
	    }	
        try {            
        	
        	int signerid = getWorkerId(args[1], hostname);
        	checkThatWorkerIsSigner(signerid,hostname);
        	
        	String certsn = args[2];
        	String issuerdn = args[3];
        	BigInteger sn = new BigInteger(certsn,16); // Test that it's a vaild number (hex)
        	AuthorizedClient authClient = new AuthorizedClient(sn.toString(16),issuerdn);
        	        	
        	this.getOutputStream().println("Removing the client certificate with SN " + certsn + " with issuerDN " + issuerdn + " from signer with id " +signerid + "\n");
        	this.getOutputStream().println("See current configuration with the listauthorizedclients command, activate it with the reload command\n\n");
        	if(getCommonAdminInterface(hostname).removeAuthorizedClient(signerid,authClient)){
        		this.getOutputStream().println("  Client Removed\n");	
        	}else{
        		this.getOutputStream().println("  Error, the given client doesn't seem to exist\n");
        	}
        	
        	printAuthorizedClients(getCommonAdminInterface(hostname).getCurrentWorkerConfig(signerid));
        	
    		this.getOutputStream().println("\n\n");
        	
        } catch (IllegalAdminCommandException e) {
        	throw e;  
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

	private void checkThatWorkerIsSigner(int signerid, String hostname) {
		// TODO Auto-generated method stub
		
	}

	public int getCommandType() {
		return TYPE_EXECUTEONMASTER;
	}
    // execute
}
