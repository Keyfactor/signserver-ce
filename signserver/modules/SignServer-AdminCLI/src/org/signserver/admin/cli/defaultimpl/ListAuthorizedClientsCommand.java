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

import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.WorkerConfig;

/**
 * Gets the current configurations list of authorized clients
 *
 * @version $Id$
 */
public class ListAuthorizedClientsCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Gets the current configurations list of authorized clients";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver listauthorizedclients <signerid> \n"
                    + "Example: signserver listauthorizedclients 1 \n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 1) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {
            int signerid = getWorkerId(args[0]);
            checkThatWorkerIsProcessable(signerid);

            WorkerConfig config = getWorkerSession().getCurrentWorkerConfig(signerid);

            this.getOutputStream().println(
                    "OBSERVE that this command displays the current configuration which\n"
                    + "doesn't have to be the same as the active configuration.\n"
                    + "Configurations are activated with the reload command. \n\n"
                    + "The current list of authorized clients to " + signerid + " are :\n");

            if (new ProcessableConfig(config).getAuthorizedClients().isEmpty()) {
                this.getOutputStream().println("  No authorized clients exists-\n");
            }

            printAuthorizedClients(config);

            this.getOutputStream().println("\n\n");
            return 0;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
}
