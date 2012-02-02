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
import java.util.Enumeration;
import java.util.Iterator;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerConfig;

/**
 * Removes a property for a given signer.
 *
 * @version $Id$
 */
public class RemoveWorkerPropertyCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Removes a property for a given signer";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException {
        if (args.length != 1) {
            throw new IllegalCommandArgumentsException("Usage: signserver removeworker  <workerid | workerName> \n"
                    + "Example 1 : signserver removeworker 1 \n"
                    + "Example 2 : signserver removeworker -host node3.someorg.com mySigner\n\n");
        }
        try {
            String workerid = args[0];

            if (workerid.substring(0, 1).matches("\\d")) {
                removeWorker(Integer.parseInt(workerid));
            } else {
                // named worker is requested
                int id = getWorkerSession().getWorkerId(workerid.trim());
                if (id == 0) {
                    throw new IllegalCommandArgumentsException("Error: No worker with the given name could be found");
                }
                removeWorker(id);
            }
            this.getOutputStream().println("\n\n");
            return 0;
        } catch (IllegalCommandArgumentsException ex) {
            throw ex;
        } catch (Exception e) {
            throw new CommandFailureException(e);
        }
    }

    private void removeGlobalProperties(int workerid) throws RemoteException, Exception {
        GlobalConfiguration gc = getGlobalConfigurationSession().getGlobalConfiguration();
        Enumeration<String> en = gc.getKeyEnumeration();
        while (en.hasMoreElements()) {
            String key = en.nextElement();
            if (key.toUpperCase().startsWith("GLOB.WORKER" + workerid)) {

                key = key.substring("GLOB.".length());
                if (getGlobalConfigurationSession().removeProperty(GlobalConfiguration.SCOPE_GLOBAL, key)) {
                    getOutputStream().println("  Global property '" + key + "' removed successfully.");
                } else {
                    getOutputStream().println("  Failed removing global property '" + key + "'.");
                }
            }
        }
    }

    private void removeWorker(int workerId) throws RemoteException, Exception {
        this.getOutputStream().println("Removing all properties related to worker with id " + workerId + "\n");
        this.getOutputStream().println("Activate the removal with the reload command\n\n");

        removeGlobalProperties(workerId);

        WorkerConfig wc = getWorkerSession().getCurrentWorkerConfig(workerId);
        Iterator<Object> iter = wc.getProperties().keySet().iterator();
        while (iter.hasNext()) {
            String key = (String) iter.next();
            if (getWorkerSession().removeWorkerProperty(workerId, key)) {
                this.getOutputStream().println("  Property '" + key + "' removed.");
            } else {
                this.getOutputStream().println("  Error, the property '" + key + "' couldn't be removed.");
            }
        }
    }
}
