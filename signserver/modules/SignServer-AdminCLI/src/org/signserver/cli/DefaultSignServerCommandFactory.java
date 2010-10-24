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
import org.signserver.cli.groupkeyservice.PregenerateKeyCommand;
import org.signserver.cli.groupkeyservice.RemoveGroupKeysCommand;
import org.signserver.cli.groupkeyservice.SwitchEncKeyCommand;
import org.signserver.cli.module.AddModuleCommand;
import org.signserver.cli.module.ListModulesCommand;
import org.signserver.cli.module.RemoveModuleCommand;
 
/**
 * Factory for General signserver Commands.
 *
 * @version $Id$
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
        if (args[0].equalsIgnoreCase("removeworker")) {
            return new RemoveWorkerPropertyCommand(args);
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
        if (args[0].equalsIgnoreCase("listauthorizedusers") && CommonAdminInterface.isMailSignerMode()) {
            return new ListAuthorizedUsersCommand(args);
        }
        if (args[0].equalsIgnoreCase("addauthorizeduser") && CommonAdminInterface.isMailSignerMode()) {
            return new AddAuthorizedUserCommand(args);
        }
        if (args[0].equalsIgnoreCase("removeauthorizeduser")  && CommonAdminInterface.isMailSignerMode()) {
            return new RemoveAuthorizedUserCommand(args);
        }
        if (args[0].equalsIgnoreCase("uploadsignercertificate")) {
            return new UploadSignerCertificateCommand(args);
        }
        if (args[0].equalsIgnoreCase("uploadsignercertificatechain")) {
            return new UploadSignerCertificateChainCommand(args);
        }
        if (args[0].equalsIgnoreCase("activatesigntoken") || args[0].equalsIgnoreCase("activatecryptotoken")) {
            return new ActivateCryptoTokenCommand(args);
        }
        if (args[0].equalsIgnoreCase("deactivatesigntoken") || args[0].equalsIgnoreCase("deactivatecryptotoken")) {
            return new DeactivateCryptoTokenCommand(args);
        }
        if (args[0].equalsIgnoreCase("generatecertreq")) {
            return new GenerateCertReqCommand(args);
        }
        if (args[0].equalsIgnoreCase("archive") && CommonAdminInterface.isSignServerMode()) {
            return getArchiveCommand(args);
        }
        if (args[0].equalsIgnoreCase("groupkeyservice") && CommonAdminInterface.isSignServerMode()) {
            return getGroupKeyServiceCommand(args);
        }
        if (args[0].equalsIgnoreCase("module")) {
            return getModuleCommand(args);
        }
        if (args[0].equalsIgnoreCase("setstatusproperty")) {
            return new SetStatusPropertyCommand(args);
        }
        if (args[0].equalsIgnoreCase("getstatusproperty")) {
            return new GetStatusPropertyCommand(args);
        }
        if (args[0].equalsIgnoreCase("getstatusproperties")) {
            return new GetStatusPropertiesCommand(args);
        }
        if (args[0].equalsIgnoreCase("generatekey")) {
            return new GenerateKeyCommand(args);
        }
        if (args[0].equalsIgnoreCase("testkey")) {
            return new TestKeyCommand(args);
        }
        return null;
        
        
        
    } // getCommand

	private IAdminCommand getGroupKeyServiceCommand(String[] args) {
	   	if (args.length < 2) {
            return null;
        }
    	 
        if (args[1].equalsIgnoreCase("switchenckey")) {
            return new SwitchEncKeyCommand(args);
        }

        if (args[1].equalsIgnoreCase("removegroupkeys")) {
            return new RemoveGroupKeysCommand(args);
        }
        
        if (args[1].equalsIgnoreCase("pregeneratekeys")) {
            return new PregenerateKeyCommand(args);
        }
		
		return null;
	}
	
	private IAdminCommand getModuleCommand(String[] args) {
	   	if (args.length < 2) {
            return null;
        }
    	 
        if (args[1].equalsIgnoreCase("add")) {
            return new AddModuleCommand(args);
        }

        if (args[1].equalsIgnoreCase("remove")) {
            return new RemoveModuleCommand(args);
        }
        
        if (args[1].equalsIgnoreCase("list")) {
            return new ListModulesCommand(args);
        }
		
		return null;
	}

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
	    	usageString +="| setproperty | setproperties | setpropertyfromfile | removeproperty | removeworker | dumpproperties ";
	    	if(CommonAdminInterface.isSignServerMode()){
	    	  usageString +="| listauthorizedclients | addauthorizedclient | removeauthorizedclient ";
	    	}else{
	    		usageString +="| listauthorizedusers | addauthorizeduser | removeauthorizeduser ";
	    	}
	    	usageString +="| uploadsignercertificate | uploadsignercertificatechain | activatecryptotoken | deactivatecryptotoken | generatecertreq | generatekey | testkey ";
	    	if(CommonAdminInterface.isSignServerMode()){	
	    		usageString +="| archive | groupkeyservice ";
	    	}
	    	usageString += "| module";
                usageString += "| getstatusproperty | getstatusproperties | setstatusproperty";
	        usageString += " >\n";
	        out.println(usageString);
	    	if(CommonAdminInterface.isSignServerMode()){
	    		out.println("Available archive commands : signserver archive < findfromarchiveid | findfromrequestip | findfromrequestcert > \n");
	    		out.println("Available groupkeyservice commands : signserver groupkeyservice < switchenckey | removegroupkeys | pregeneratekeys > \n");	    		
	    	}
	    	out.println("Available module commands : signserver module < add | remove | list > \n");
	    	out.println("Each basic command give more help");

	    }
} 
