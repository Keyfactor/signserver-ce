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
 * Get a property for a given worker.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class GetPropertyCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Gets a property for a given worker";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver getproperty <signerid | signerName | global | node> <propertykey>\n"
                + "Example 1: signserver getproperty 1 defaultKey\n"
                + "Example 2: signserver getproperty mySigner defaultKey\n"
                + "Example 3: signserver getproperty global WORKER6.CLASSPATH\n\n";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException,
            CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 2) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        
        try {
            final String propertykey = args[1];
            final String workerid = args[0];

            if (workerid.substring(0, 1).matches("\\d")) {
                getWorkerProperty(Integer.parseInt(workerid), propertykey);
            } else {
                if (workerid.trim().equalsIgnoreCase("GLOBAL")) {
                    getGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, propertykey);
                } else {
                    if (workerid.trim().equalsIgnoreCase("NODE")) {
                        getGlobalProperty(GlobalConfiguration.SCOPE_NODE, propertykey);

                    } else {
                        // named worker is requested
                        int id = getWorkerSession().getWorkerId(workerid);
                        if (id == 0) {
                            throw new CommandFailureException("Error: No such worker");
                        }
                        getWorkerProperty(id, propertykey);
                    }
                }
            }

            this.getOutputStream().println("\n\n");
            return 0;

        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
    
    private void getGlobalProperty(String scope, String key) throws RemoteException {
        final String propertyValue = getGlobalConfigurationSession().getGlobalConfiguration().getProperty(scope, key);
    
        if (propertyValue != null) {
            this.getOutputStream().println("Value of global property " + key +
                    " with scope " + scope + ": " + propertyValue + "\n");
        } else {
            this.getOutputStream().println("No such global property\n");
        }
    }

    private void getWorkerProperty(int workerId, String propertykey) throws RemoteException {
        final String propertyValue = getWorkerSession().getCurrentWorkerConfig(workerId).getProperty(propertykey);
    
        if (propertyValue != null) {
            this.getOutputStream().println("Value of property " + propertykey +
                    " for worker " + workerId + ": " + propertyValue + "\n");
        } else {
            this.getOutputStream().println("No such property " + propertykey +
                    " for worker " + workerId + "\n");
        }
    }

}
