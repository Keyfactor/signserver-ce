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

import java.io.PrintStream;

import org.signserver.cli.archive.FindFromArchiveIdCommand;
import org.signserver.cli.archive.FindFromRequestCertCommand;
import org.signserver.cli.archive.FindFromRequestIPCommand;
 
/**
 * Factory for General signserver Commands.
 *
 * @version $Id: DefaultSignServerCommandFactory.java,v 1.1 2007-12-04 15:35:10 herrvendil Exp $
 */
public class DefaultSignServerCommandFactory implements ISignServerCommandFactory {


    /* (non-Javadoc)
	 * @see org.signserver.cli.ISignServerCommandFactory#getCommand(java.lang.String[])
	 */
    public IAdminCommand getCommand(String[] args) {
    	
    	if (args.length < 1) {
            return null;
        }
    	 
        if (args[0].equalsIgnoreCase("getstatus")) {
            return new GetStatusCommand(args);
        }
        if (args[0].equalsIgnoreCase("getconfig")) {
            return new GetConfigCommand(args);
        }
        if (args[0].equalsIgnoreCase("reload")) {
            return new ReloadCommand(args);
        }
        if (args[0].equalsIgnoreCase("resync") && CommonAdminInterface.isSignServerMode()) {
            return new ResyncCommand(args);
        }
        if (args[0].equalsIgnoreCase("setproperty")) {
            return new SetPropertyCommand(args);
        }
        if (args[0].equalsIgnoreCase("setproperties")) {
            return new SetPropertiesCommand(args);
        }        
        if (args[0].equalsIgnoreCase("setpropertyfromfile")) {
            return new SetPropertyFromFileCommand(args);
        }
        if (args[0].equalsIgnoreCase("removeproperty")) {
            return new RemovePropertyCommand(args);
        }
        if (args[0].equalsIgnoreCase("dumpproperties")) {
            return new DumpPropertiesCommand(args);
        }
        if (args[0].equalsIgnoreCase("listauthorizedclients") && CommonAdminInterface.isSignServerMode()) {
            return new ListAuthorizedClientsCommand(args);
        }
        if (args[0].equalsIgnoreCase("addauthorizedclient") && CommonAdminInterface.isSignServerMode()) {
            return new AddAuthorizedClientCommand(args);
        }
        if (args[0].equalsIgnoreCase("removeauthorizedclient")  && CommonAdminInterface.isSignServerMode()) {
            return new RemoveAuthorizedClientCommand(args);
        }
        if (args[0].equalsIgnoreCase("uploadsignercertificate")) {
            return new UploadSignerCertificateCommand(args);
        }
        if (args[0].equalsIgnoreCase("uploadsignercertificatechain")) {
            return new UploadSignerCertificateChainCommand(args);
        }
        if (args[0].equalsIgnoreCase("activatesigntoken")) {
            return new ActivateSignTokenCommand(args);
        }
        if (args[0].equalsIgnoreCase("deactivatesigntoken")) {
            return new DeactivateSignTokenCommand(args);
        }
        if (args[0].equalsIgnoreCase("generatecertreq")) {
            return new GenerateCertReqCommand(args);
        }
        if (args[0].equalsIgnoreCase("archive") && CommonAdminInterface.isSignServerMode()) {
            return getArchiveCommand(args);
        }
        return null;
        
        
        
    } // getCommand

	private static IAdminCommand getArchiveCommand(String[] args) {
	   	if (args.length < 2) {
            return null;
        }
    	 
        if (args[1].equalsIgnoreCase("findfromarchiveid")) {
            return new FindFromArchiveIdCommand(args);
        }

        if (args[1].equalsIgnoreCase("findfromrequestip")) {
            return new FindFromRequestIPCommand(args);
        }
        
        if (args[1].equalsIgnoreCase("findfromrequestcert")) {
            return new FindFromRequestCertCommand(args);
        }
		
		return null;
	}
	
	/* (non-Javadoc)
	 * @see org.signserver.cli.ISignServerCommandFactory#outputHelp(java.io.PrintStream)
	 */
	public void outputHelp(PrintStream out) {
	    	
	    	String usageString = "Usage: signserver < getstatus | getconfig | reload ";
	    	if(CommonAdminInterface.isSignServerMode()){
	    		usageString +="| resync ";
	    	}
	    	usageString +="| setproperty | setproperties | setpropertyfromfile | removeproperty | dumpproperties ";
	    	if(CommonAdminInterface.isSignServerMode()){
	    	  usageString +="| listauthorizedclients | addauthorizedclient | removeauthorizedclient ";
	    	}
	    	usageString +="| uploadsignercertificate | uploadsignercertificatechain | activatesigntoken | deactivatesigntoken | generatecertreq ";
	    	if(CommonAdminInterface.isSignServerMode()){	
	    		usageString +="| archive";
	    	}
	        usageString+= "> \n";
	        out.println(usageString);
	    	if(CommonAdminInterface.isSignServerMode()){
	    		out.println("Available archive commands : Usage: signserver archive < findfromarchiveid | findfromrequestip | findfromrequestcert > \n");
	    	}
	    	out.println("Each basic command give more help");

	    }
} 
