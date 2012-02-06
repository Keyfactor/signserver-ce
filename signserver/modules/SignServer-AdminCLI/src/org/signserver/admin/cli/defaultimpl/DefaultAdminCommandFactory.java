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
package org.signserver.admin.cli.defaultimpl;

import org.signserver.admin.cli.defaultimpl.archive.FindFromArchiveIdCommand;
import org.signserver.admin.cli.defaultimpl.archive.FindFromRequestCertCommand;
import org.signserver.admin.cli.defaultimpl.archive.FindFromRequestIPCommand;
import org.signserver.admin.cli.defaultimpl.groupkeyservice.PregenerateKeysCommand;
import org.signserver.admin.cli.defaultimpl.groupkeyservice.RemoveGroupKeysCommand;
import org.signserver.admin.cli.defaultimpl.groupkeyservice.SwitchEncKeyCommand;
import org.signserver.admin.cli.spi.AdminCommandFactory;
import org.signserver.cli.spi.AbstractCommandFactory;


/**
 * CommandFactory for the default admin commands used by the Admin CLI.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class DefaultAdminCommandFactory extends AbstractCommandFactory implements AdminCommandFactory {

    @Override
    protected void registerCommands() {
        // Top level commands
        put("activatecryptotoken", ActivateCryptoTokenCommand.class);
        put("activatesigntoken", ActivateCryptoTokenCommand.class, false);
        put("addauthorizedclient", AddAuthorizedClientCommand.class);
        put("deactivatecryptotoken", DeactivateCryptoTokenCommand.class);
        put("deactivatesigntoken", DeactivateCryptoTokenCommand.class, false);
        put("dumpproperties", DumpPropertiesCommand.class);
        put("generatecertreq", GenerateCertReqCommand.class);
        put("generatekey", GenerateKeyCommand.class);
        put("getconfig", GetConfigCommand.class);
        put("getstatus", GetStatusCommand.class);
        put("getstatusproperties", GetStatusPropertiesCommand.class);
        put("getstatusproperty", GetStatusPropertyCommand.class);
        put("listauthorizedclients", ListAuthorizedClientsCommand.class);
        put("reload", ReloadCommand.class);
        put("removeauthorizedclient", RemoveAuthorizedClientCommand.class);
        put("removeproperty", RemovePropertyCommand.class);
        put("removeworker", RemoveWorkerPropertyCommand.class);
        put("renewsigner", RenewSignerCommand.class);
        put("resync", ResyncCommand.class);
        put("setproperties", SetPropertiesCommand.class);
        put("setproperty", SetPropertyCommand.class);
        put("setpropertyfromfile", SetPropertyFromFileCommand.class);
        put("setstatusproperty", SetStatusPropertyCommand.class);
        put("testkey", TestKeyCommand.class);
        put("uploadsignercertificatechain", UploadSignerCertificateChainCommand.class);
        put("uploadsignercertificate", UploadSignerCertificateCommand.class);
        put("wsadmins", WSAdminsCommand.class);
        
        // Archive commands
        put("archive", "findfromarchiveid", FindFromArchiveIdCommand.class);
        put("archive", "findfromrequestcert", FindFromRequestCertCommand.class);
        put("archive", "findfromrequestip", FindFromRequestIPCommand.class);
        
        // Groupkeyservice commands
        put("groupkeyservice", "pregeneratekeys", PregenerateKeysCommand.class);
        put("groupkeyservice", "removegroupkeys", RemoveGroupKeysCommand.class);
        put("groupkeyservice", "switchenckey", SwitchEncKeyCommand.class);
    }

}
