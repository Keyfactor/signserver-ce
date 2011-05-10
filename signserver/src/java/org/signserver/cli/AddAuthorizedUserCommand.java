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
 * Adds an authorized user to a mail signer installation
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class AddAuthorizedUserCommand extends BaseCommand {
	
	
	
    /**
     * Creates a new instance of SetPropertyCommand
     *
     * @param args command line arguments
     */
    public AddAuthorizedUserCommand(String[] args) {
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
	       throw new IllegalAdminCommandException("Usage: signserver addauthorizeduser <username> <password>\n" + 
	       		                                  "Example: signserver addauthorizeduser user1 foo123\n\n");	       
	    }	
        try {            
        	
        	String username = args[1];
        	String password = args[2];        	
        	        	        
        	this.getOutputStream().println("Adding the user with username " + username + " as authorized SMTP user\n");
        	this.getOutputStream().println("See current authorized users with the listauthorizedusers command, no need to activate configuration with reload.\n");		                       
        	
        	getCommonAdminInterface(hostname).addAuthorizedUser(username, password);     	        	
        	        	        	
    		this.getOutputStream().println("\n\n");
        	
        } catch (IllegalAdminCommandException e) {
        	throw e;  
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

	public int getCommandType() {
		return TYPE_EXECUTEONMASTER;
	}

    // execute
}
