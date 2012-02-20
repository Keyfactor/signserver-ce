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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import org.signserver.statusrepo.common.StatusEntry;

/**
 * Gets all status properties and their expiration time.
 *
 * @version $Id$
 */
public class GetStatusPropertiesCommand extends BaseCommand {
    
    private static final String FORMAT = "%-20s %-25s %-25s %s";
    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");

    /**
     * Creates a new instance of GetStatusPropertiesCommand.
     *
     * @param args command line arguments
     */
    public GetStatusPropertiesCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command.
     *
     * @param hostname host to execute on
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    @Override
    public void execute(final String hostname)
            throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 1) {
            throw new IllegalAdminCommandException(
                    "Usage: signserver getstatusproperties\n"
                    + "Example 1: signserver setstatusproperty TIMESOURCE0_INSYNC true\n"
                    + "Example 2: signserver setstatusproperty TIMESOURCE0_INSYNC true "
                    + "1263375588000\n\n");
        }
        try {

            final Map<String, StatusEntry> properties =
                    getCommonAdminInterface(hostname).getAllEntries();

            getOutputStream().println(String.format(FORMAT, "Property", "Updated", "Expiration", "Value"));
            
            for (Map.Entry<String, StatusEntry> entry : properties.entrySet()) {
                StatusEntry status = entry.getValue();    
                if (status == null) {
                    getOutputStream().println(String.format(FORMAT, entry.getKey(), "-", "-", "-"));
                } else {
                    getOutputStream().println(String.format(FORMAT, entry.getKey(), format(status.getUpdateTime()), format(status.getExpirationTime()), status.getValue()));
                }
            }

            this.getOutputStream().println("\n\n");

        } catch (IllegalAdminCommandException e) {
            throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    @Override
    public int getCommandType() {
        return TYPE_EXECUTEONMASTER;
    }
    
    private static String format(long timestamp) {
        if (timestamp <= 0) {
            return "-";
        } else {
            return SDF.format(new Date(timestamp));
        }
    }
}
