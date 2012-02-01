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

/**
 * Reloads the current configuration
 *
 * @version $Id$
 */
public class ReloadCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Reloads the current configuration";
    }

    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException {
        if (args.length != 1) {
            throw new IllegalCommandArgumentsException("Usage: signserver reload <worker id or name | all> \n\n"
                    + "Example 1 : signserver reload all \n"
                    + "Example 2 : signserver reload myWorker \n"
                    + "Example 1 : signserver reload 1 \n");
        }
        try {
            int workerId = 0;

            if (!args[1].equalsIgnoreCase("all")) {
                workerId = getWorkerId(args[0]);
                if (workerId == 0) {
                    throw new IllegalAdminCommandException("Error: Worker Id cannot be 0.");
                }
            }

            getWorkerSession().reloadConfiguration(workerId);

            this.getOutputStream().println("SignServer reloaded successfully\n");
            this.getOutputStream().println("Current configuration is now activated.\n");
            return 0;
        } catch (Exception e) {
            throw new CommandFailureException(e);
        }
    }
}
