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

import java.util.List;

import org.signserver.common.MailSignerUser;


/**
 * Gets the current list of authorized users of performing SMTP AUTH
 *
 * @version $Id$
 * @author Philip Vendil
 */
public class ListAuthorizedUsersCommand extends BaseCommand {
	
	
    /**
     * Creates a new instance of ListAuthorizedClientsCommand
     *
     * @param args command line arguments
     */
    public ListAuthorizedUsersCommand(String[] args) {
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
	       throw new IllegalAdminCommandException("Usage: signserver listauthorizedusers \n\n");	       
	    }	
        try {            
        	

        	List<MailSignerUser> users = this.getCommonAdminInterface(hostname).getAuthorizedUsers();
        	
        	this.getOutputStream().println(
         			                       "OBSERVE Unlike the behaviour of the signserver, authorized users " +
         			                       "are activated immediatly and there is no need for a 'reload' command.\n\n" +
         			                       "Authorization applies for all mail signers in the application.\n\n" +
         			                       "Authorized users for this mail signer are: \n");
        	
        	if(users.size() == 0){
        		this.getOutputStream().println("  No authorized users exists.\n");
        	}else{
        	  for(MailSignerUser user : users){
        		  this.getOutputStream().println("  " + user.getUserName());
        	  }
        	}

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
