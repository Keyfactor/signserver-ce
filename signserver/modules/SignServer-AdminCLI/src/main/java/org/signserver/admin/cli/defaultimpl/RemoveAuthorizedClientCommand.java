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

import java.math.BigInteger;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.AuthorizedClient;

/**
 * removes an authorized client from a given signer
 *
 * @version $Id$
 */
public class RemoveAuthorizedClientCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Removes an authorized client from a given signer";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver removeauthorizedclient <signerid> <certificatesn (hex)> <issuerd>\n"
                    + "Example: signserver removeauthorizedclient 1 EF34242D232 \"CN=Test Root CA\"\n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 3) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {

            int signerid = getWorkerId(args[0]);

            String certsn = args[1];
            String issuerdn = args[2];
            BigInteger sn = new BigInteger(certsn, 16); // Test that it's a vaild number (hex)
            AuthorizedClient authClient = new AuthorizedClient(sn.toString(16), issuerdn);

            this.getOutputStream().println("Removing the client certificate with SN " + certsn + " with issuerDN " + issuerdn + " from signer with id " + signerid + "\n");
            this.getOutputStream().println("See current configuration with the listauthorizedclients command, activate it with the reload command\n\n");
            if (getWorkerSession().removeAuthorizedClient(signerid, authClient)) {
                this.getOutputStream().println("  Client Removed\n");
            } else {
                this.getOutputStream().println("  Error, the given client doesn't seem to exist\n");
            }

            printAuthorizedClients(getWorkerSession().getCurrentWorkerConfig(signerid));

            this.getOutputStream().println("\n\n");
            return 0;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
}
