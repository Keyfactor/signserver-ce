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

import org.signserver.statusrepo.common.StatusEntry;

/**
 * Gets a status property.
 *
 * @version $Id$
 */
public class GetStatusPropertyCommand extends BaseCommand {

    /**
     * Creates a new instance of SetPropertyCommand
     *
     * @param args command line arguments
     */
    public GetStatusPropertyCommand(final String[] args) {
        super(args);
    }

    /**
     * Runs the command.
     *
     * @param hostname host to execute on
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException,
            ErrorAdminCommandException {
        if (args.length != 2) {
            throw new IllegalAdminCommandException(
                    "Usage: signserver getstatusproperty <propertykey>\n"
                    + "Example 1: signserver getstatusproperty INSYNC\n\n");
        }
        try {
            final StatusEntry entry = getCommonAdminInterface(hostname).getValidEntry(args[1]);

            this.getOutputStream().print(args[1] + " = ");
            if (entry != null) {
                this.getOutputStream().println(entry.getValue());
            } else {
                this.getOutputStream().println();
            }
        } catch (IllegalAdminCommandException e) {
            throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    public int getCommandType() {
        return TYPE_EXECUTEONMASTER;
    }
}
