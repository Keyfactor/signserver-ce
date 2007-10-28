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
 * Factory for General signserver Commands.
 *
 * @version $Id: SignServerCommandFactory.java,v 1.3 2007-10-28 12:23:55 herrvendil Exp $
 */
public class SignServerCommandFactory {
    /**
     * Cannot create an instance of this class, only use static methods.
     */
    private SignServerCommandFactory() {
    }

    /**
     * Returns an Admin Command object based on contents in args[0].
     *
     * @param args array of arguments typically passed from main().
     *
     * @return Command object or null if args[0] does not specify a valid command.
     */
    public static IAdminCommand getCommand(String[] args) {
    	
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
} 
