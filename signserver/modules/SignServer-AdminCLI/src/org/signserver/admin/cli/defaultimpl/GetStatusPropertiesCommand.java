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

import java.util.Map;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.StatusRepositoryData;

/**
 * Gets all status properties and their expiration time.
 *
 * @version $Id$
 */
public class GetStatusPropertiesCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Gets all status properties and their expiration time";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver getstatusproperties\n"
                    + "Example 1: signserver setstatusproperty INSYNC true\n"
                    + "Example 2: signserver setstatusproperty INSYNC true "
                    + "1263375588000\n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 0) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {

            final Map<String, StatusRepositoryData> properties =
                    getStatusRepositorySession().getProperties();

            for (Map.Entry<String, StatusRepositoryData> entry : properties.entrySet()) {
                getOutputStream().println(entry.getKey() + ", "
                        + entry.getValue().getExpiration() + " = \""
                        + entry.getValue().getValue() + "\"");
            }

            this.getOutputStream().println("\n\n");
            return 0;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
}
