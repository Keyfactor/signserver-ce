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
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ResyncException;

/**
 * Resynchronizes an out-of-sync Global Configuration.
 *
 * @version $Id$
 */
public class ResyncCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Resynchronizes an out-of-sync Global Configuration";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver resync <sure> \n\n"
                    + "Example 1 : signserver resync true \n"
                    + "Example 2 : signserver resync yes \n"
                    + "This command resyncronizes a out-of-sync Global Configuration.\n"
                    + "Warning: Only use this commando if you know what you are doing.";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 1) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {
            if (args[0].equalsIgnoreCase("true") || args[0].equalsIgnoreCase("yes")) {
                this.getOutputStream().println("Resyncronizing database...");
                try {
                    if (this.getGlobalConfigurationSession().getGlobalConfiguration().getState().equals(GlobalConfiguration.STATE_OUTOFSYNC)) {
                        this.getGlobalConfigurationSession().resync();
                        this.getOutputStream().println("Syncronization was successful\n");
                    } else {
                        this.getOutputStream().println("Global configuration is not out of sync. Operation aborted.\n");
                        return -2;
                    }
                } catch (ResyncException e) {
                    this.getOutputStream().println("Syncronization failed: " + e.getMessage());
                    return -2;
                }
            } else {
                this.getOutputStream().println("Syncronization aborted.");
                return -2;
            }
            return 0;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
}
