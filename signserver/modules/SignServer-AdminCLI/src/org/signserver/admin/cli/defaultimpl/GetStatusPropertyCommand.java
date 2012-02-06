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

/**
 * Gets a status property.
 *
 * @version $Id$
 */
public class GetStatusPropertyCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Gets a status property";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver getstatusproperty <propertykey>\n"
                    + "Example 1: signserver getstatusproperty INSYNC\n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 1) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {
            final String value = getStatusRepositorySession().getProperty(args[0]);

            this.getOutputStream().print(args[0] + " = ");
            this.getOutputStream().println(value);
            this.getOutputStream().println("\n\n");
            return 0;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
}
