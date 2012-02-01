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

import java.rmi.RemoteException;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.GlobalConfiguration;

/**
 * removes a property for a given signer
 *
 * @version $Id$
 */
public class RemovePropertyCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Removes a property for a given signer";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException {
        if (args.length != 3) {
            throw new IllegalCommandArgumentsException("Usage: signserver <-host hostname (optional)> removeproperty  <workerid | workerName | global | node> <propertykey>\n"
                    + "Example 1 : signserver removeproperty 1 defaultKey\n"
                    + "Example 2 : signserver removeproperty -host node3.someorg.com mySigner defaultKey\n\n");
        }
        try {

            String propertykey = args[2];

            String workerid = args[1];

            if (workerid.substring(0, 1).matches("\\d")) {
                removeWorkerProperty(Integer.parseInt(workerid), propertykey);
            } else {
                if (workerid.trim().equalsIgnoreCase("GLOBAL")) {
                    removeGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, propertykey);
                } else {
                    if (workerid.trim().equalsIgnoreCase("NODE")) {
                        removeGlobalProperty(GlobalConfiguration.SCOPE_NODE, propertykey);

                    } else {
                        // named worker is requested
                        int id = getWorkerSession().getWorkerId(workerid);
                        if (id == 0) {
                            throw new IllegalAdminCommandException("Error: No worker with the given name could be found");
                        }
                        removeWorkerProperty(id, propertykey);
                    }
                }
            }
            this.getOutputStream().println("\n\n");
            return 0;
        } catch (Exception e) {
            throw new CommandFailureException(e);
        }
    }

    private void removeGlobalProperty(String scope, String key) throws RemoteException, Exception {
        this.getOutputStream().println("removing the global property " + key + " with scope " + scope + "\n");
        this.getOutputStream().println("See current configuration with the getconfig command, activate it with the reload command");

        if (key.toUpperCase().startsWith("GLOB.")) {
            key = key.substring("GLOB.".length());
        }
        if (key.toUpperCase().startsWith("NODE.")) {
            key = key.substring("NODE.".length());
        }
        if (getGlobalConfigurationSession().removeProperty(scope, key)) {
            this.getOutputStream().println("  Property Removed\n");
        } else {
            this.getOutputStream().println("  Error, the property " + key + " doesn't seem to exist\n");
        }
    }

    private void removeWorkerProperty(int workerId, String propertykey) throws RemoteException, Exception {
        this.getOutputStream().println("Removing the property " + propertykey + " from worker " + workerId + "\n");
        this.getOutputStream().println("See current configuration with the getconfig command, activate it with the reload command\n\n");
        if (getWorkerSession().removeWorkerProperty(workerId, propertykey)) {
            this.getOutputStream().println("  Property Removed\n");
        } else {
            this.getOutputStream().println("  Error, the property " + propertykey + " doesn't seem to exist\n");
        }
    }
}
