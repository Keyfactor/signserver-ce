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

import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.statusrepo.common.NoSuchPropertyException;
import org.signserver.statusrepo.common.StatusEntry;

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
            final StatusEntry entry = getStatusRepositorySession().getValidEntry(args[0]);
            this.getOutputStream().print(args[0] + " = ");
            if (entry != null) {
                this.getOutputStream().println(entry.getValue());
            } else {
                this.getOutputStream().println();
            }
            return CommandLineInterface.RETURN_SUCCESS;
        } catch (NoSuchPropertyException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
}
