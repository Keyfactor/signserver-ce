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
 * Adds an authorized client to a signer
 *
 * @version $Id$
 */
public class AddAuthorizedClientCommand extends BaseCommand {

    /**
     * Creates a new instance of SetPropertyCommand
     *
     * @param args command line arguments
     */
    public AddAuthorizedClientCommand(String[] args) {
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
            throw new IllegalAdminCommandException("Usage: signserver addauthorizedclient <signerid> <certificatesn (hex)> <issuerd>\n"
                    + "Example: signserver addauthorizedclient 1 EF34242D2324 \"CN=Test Root CA\"\n\n");
        }

        try {
            int signerid = getWorkerId(args[1], hostname);
            checkThatWorkerIsProcessable(signerid, hostname);

            String certsn = args[2];
            String issuerdn = args[3];
            BigInteger sn = new BigInteger(certsn, 16); // Test that it's a vaild number (hex)
            AuthorizedClient authClient = new AuthorizedClient(sn.toString(16), issuerdn);

            this.getOutputStream().println("Adding the client certificate with sn " + certsn + " and issuerDN : " + issuerdn + " for signer " + signerid + "\n");
            this.getOutputStream().println("See current configuration with the listauthorizedclients command, activate it with the reload command\n");

            getCommonAdminInterface(hostname).addAuthorizedClient(signerid, authClient);


            printAuthorizedClients(getCommonAdminInterface(hostname).getCurrentWorkerConfig(signerid));

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
