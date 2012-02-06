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
 * Sets a status property.
 *
 * @version $Id$
 */
public class SetStatusPropertyCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Sets a status property";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver setstatusproperty <propertykey> "
                    + "<propertyvalue> <expiration (optional)>\n"
                    + "Example 1: signserver setstatusproperty INSYNC true\n"
                    + "Example 2: signserver setstatusproperty INSYNC true "
                    + "1263297710\n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length < 2 || args.length > 3) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {

            if (args.length < 3) {
                setStatusProperty(args[0], args[1]);
            } else {
                setStatusProperty(args[0], args[1], Long.valueOf(args[2]));
            }
            this.getOutputStream().println("\n\n");
            return 0;
        } catch (IllegalCommandArgumentsException e) {
            throw e;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }

    private void setStatusProperty(final String key, final String value) throws Exception {
        getStatusRepositorySession().setProperty(key, value);
    }

    private void setStatusProperty(final String key, final String value, final long expiration) throws Exception {
        getStatusRepositorySession().setProperty(key, value, expiration);
    }
}
