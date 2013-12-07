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
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.GlobalConfiguration;

/**
 * Sets a property for a given workerid
 *
 * @version $Id$
 */
public class SetPropertyCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Sets a property for a given worker";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver setproperty <signerid | signerName | global | node> <propertykey> <propertyvalue>\n"
                    + "Example 1: signserver setproperty 1 defaultKey c21cc935b284929beac36d66658106018b2c4ee5\n"
                    + "Example 2: signserver setproperty mySigner defaultKey c21cc935b284929beac36d66658106018b2c4ee5\n"
                    + "Example 3: signserver setproperty global WORKER6.CLASSPATH some.org.SomeWorkerClass\n"
                    + "Example 4: signserver setproperty -host node3.someorg.com node SOMENODEDATA 123456\n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 3) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {
            String propertykey = args[1];
            String propertyvalue = args[2];

            String workerid = args[0];

            if (workerid.substring(0, 1).matches("\\d")) {
                setWorkerProperty(Integer.parseInt(workerid), propertykey, propertyvalue);
            } else {
                if (workerid.trim().equalsIgnoreCase("GLOBAL")) {
                    setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, propertykey, propertyvalue);
                } else {
                    if (workerid.trim().equalsIgnoreCase("NODE")) {
                        setGlobalProperty(GlobalConfiguration.SCOPE_NODE, propertykey, propertyvalue);

                    } else {
                        // named worker is requested
                        int id = getWorkerSession().getWorkerId(workerid);
                        if (id == 0) {
                            throw new CommandFailureException("Error: No such worker");
                        }
                        setWorkerProperty(id, propertykey, propertyvalue);
                    }
                }
            }

            this.getOutputStream().println("\n\n");
            return 0;

        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }

    private void setGlobalProperty(String scope, String key, String value) throws RemoteException {
        this.getOutputStream().println("Setting the global property " + key + " to " + value + " with scope " + scope + "\n");
        this.getOutputStream().println("See current configuration with the getconfig command, activate it with the reload command");

        getGlobalConfigurationSession().setProperty(scope, key, value);
    }

    private void setWorkerProperty(int workerId, String propertykey, String propertyvalue) throws RemoteException {
        this.getOutputStream().println("Setting the property " + propertykey + " to " + propertyvalue + " for worker " + workerId + "\n");
        this.getOutputStream().println("See current configuration with the getconfig command, activate it with the reload command");

        getWorkerSession().setWorkerProperty(workerId, propertykey, propertyvalue);
    }
}
