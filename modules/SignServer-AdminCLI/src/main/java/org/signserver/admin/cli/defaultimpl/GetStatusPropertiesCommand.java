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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.statusrepo.common.StatusEntry;

/**
 * Gets all status properties and their expiration time.
 *
 * @version $Id$
 */
public class GetStatusPropertiesCommand extends AbstractAdminCommand {

    private static final String FORMAT = "%-20s %-25s %-25s %s";
    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");
    
    @Override
    public String getDescription() {
        return "Gets all status properties and their expiration time";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver getstatusproperties\n"
                    + "Example 1: signserver setstatusproperty TIMESOURCE0_INSYNC true\n"
                    + "Example 2: signserver setstatusproperty TIMESOURCE0_INSYNC true "
                    + "1263375588000\n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 0) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {

            final Map<String, StatusEntry> properties =
                    getStatusRepositorySession().getAllEntries();

            
            getOutputStream().println(String.format(FORMAT, "Property", "Updated", "Expiration", "Value"));
            
            for (Map.Entry<String, StatusEntry> entry : properties.entrySet()) {
                StatusEntry status = entry.getValue();    
                if (status == null) {
                    getOutputStream().println(String.format(FORMAT, entry.getKey(), "-", "-", "-"));
                } else {
                    getOutputStream().println(String.format(FORMAT, entry.getKey(), format(status.getUpdateTime()), format(status.getExpirationTime()), status.getValue()));
                }
            }

            getOutputStream().println("\n\n");
            return 0;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
    
    private static String format(long timestamp) {
        if (timestamp <= 0) {
            return "-";
        } else {
            return SDF.format(new Date(timestamp));
        }
    }
}
