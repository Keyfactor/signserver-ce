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

/**
 * Sets a status property.
 *
 * @version $Id$
 */
public class SetStatusPropertyCommand extends BaseCommand {

    /**
     * Creates a new instance of SetPropertyCommand.
     *
     * @param args command line arguments
     */
    public SetStatusPropertyCommand(final String[] args) {
        super(args);
    }

    /**
     * Runs the command.
     *
     * @param hostname host to execute on
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(final String hostname)
            throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 3 || args.length > 4) {
            throw new IllegalAdminCommandException(
                    "Usage: signserver setstatusproperty <propertykey> "
                    + "<propertyvalue> <expiration (optional)>\n"
                    + "Example 1: signserver setstatusproperty INSYNC true\n"
                    + "Example 2: signserver setstatusproperty INSYNC true "
                    + "1263297710\n\n");
        }
        try {

            if (args.length < 4) {
                setStatusProperty(hostname, args[1], args[2]);
            } else {
                setStatusProperty(hostname, args[1], args[2], Long.valueOf(
                        args[3]));
            }
            this.getOutputStream().println("\n\n");

        } catch (IllegalAdminCommandException e) {
            throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    private void setStatusProperty(final String hostname, final String key,
            final String value) throws Exception {
        getCommonAdminInterface(hostname).setStatusProperty(key, value);
    }

    private void setStatusProperty(final String hostname, final String key,
            final String value, final long expiration) throws Exception {
        getCommonAdminInterface(hostname).setStatusProperty(key, value,
                expiration);
    }

    public int getCommandType() {
        return TYPE_EXECUTEONMASTER;
    }
}
