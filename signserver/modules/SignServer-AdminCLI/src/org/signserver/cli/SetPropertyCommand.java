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

import java.rmi.RemoteException;

import org.signserver.common.GlobalConfiguration;

/**
 * Sets a property for a given workerid
 *
 * @version $Id$
 */
public class SetPropertyCommand extends BaseCommand {

    /**
     * Creates a new instance of SetPropertyCommand
     *
     * @param args command line arguments
     */
    public SetPropertyCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length != 4) {
            throw new IllegalAdminCommandException("Usage: signserver setproperty <-host hostname (optional)> <signerid | signerName | global | node> <propertykey> <propertyvalue>\n"
                    + "Example 1: signserver setproperty 1 defaultKey c21cc935b284929beac36d66658106018b2c4ee5\n"
                    + "Example 2: signserver setproperty mySigner defaultKey c21cc935b284929beac36d66658106018b2c4ee5\n"
                    + "Example 3: signserver setproperty global WORKER6.CLASSPATH some.org.SomeWorkerClass\n"
                    + "Example 4: signserver setproperty -host node3.someorg.com node SOMENODEDATA 123456\n\n");
        }
        try {

            String propertykey = args[2];
            String propertyvalue = args[3];

            String workerid = args[1];

            if (workerid.substring(0, 1).matches("\\d")) {
                setWorkerProperty(Integer.parseInt(workerid), hostname, propertykey, propertyvalue);
            } else {
                if (workerid.trim().equalsIgnoreCase("GLOBAL")) {
                    setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, hostname, propertykey, propertyvalue);
                } else {
                    if (workerid.trim().equalsIgnoreCase("NODE")) {
                        setGlobalProperty(GlobalConfiguration.SCOPE_NODE, hostname, propertykey, propertyvalue);

                    } else {
                        // named worker is requested
                        int id = getCommonAdminInterface(hostname).getWorkerId(workerid);
                        if (id == 0) {
                            throw new IllegalAdminCommandException("Error: No worker with the given name could be found");
                        }
                        setWorkerProperty(id, hostname, propertykey, propertyvalue);
                    }
                }
            }

            this.getOutputStream().println("\n\n");

        } catch (IllegalAdminCommandException e) {
            throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    private void setGlobalProperty(String scope, String hostname, String key, String value) throws RemoteException, Exception {
        this.getOutputStream().println("Setting the global property " + key + " to " + value + " with scope " + scope + "\n");
        this.getOutputStream().println("See current configuration with the getconfig command, activate it with the reload command");

        getCommonAdminInterface(hostname).setGlobalProperty(scope, key, value);
    }

    // execute
    public int getCommandType() {
        return TYPE_EXECUTEONMASTER;
    }

    private void setWorkerProperty(int workerId, String hostname, String propertykey, String propertyvalue) throws RemoteException, Exception {
        this.getOutputStream().println("Setting the property " + propertykey + " to " + propertyvalue + " for worker " + workerId + "\n");
        this.getOutputStream().println("See current configuration with the getconfig command, activate it with the reload command");

        getCommonAdminInterface(hostname).setWorkerProperty(workerId, propertykey, propertyvalue);
    }
}
