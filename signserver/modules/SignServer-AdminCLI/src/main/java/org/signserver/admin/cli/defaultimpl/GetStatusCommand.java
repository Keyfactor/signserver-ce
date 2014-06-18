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
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.WorkerStatus;

/**
 * Gets the current status of the given worker
 *
 * @version $Id$
 */
public class GetStatusCommand extends AbstractCommand {

    private AdminCommandHelper helper = new AdminCommandHelper();
    
    private static final String ERROR_MESSAGE = 
            "Usage: signserver getstatus <complete | brief> <workerId | workerName | all> \n"
                + "Example 1 : signserver getstatus complete all \n"
                + "Example 2 : signserver getstatus brief 1 \n"
                + "Example 3 : signserver getstatus complete mySigner \n\n";

    @Override
    public String getDescription() {
        return "Gets a status report from one or all workers";
    }

    @Override
    public String getUsages() {
        return ERROR_MESSAGE;
    }
    
    @Override
    public int execute(String[] args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 2) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {

            String mode = args[0];

            boolean allSigners = false;
            if (args[1].equalsIgnoreCase("all")) {
                allSigners = true;
            }

            if (!(mode.equalsIgnoreCase("complete") || mode.equalsIgnoreCase("brief"))) {
                throw new IllegalCommandArgumentsException(ERROR_MESSAGE);
            }

            boolean complete = mode.equalsIgnoreCase("complete");

            out.println("Current version of server is : " + helper.getGlobalConfigurationSession().getGlobalConfiguration().getAppVersion() + "\n\n");

            if (allSigners) {
                if (complete) {
                    displayGlobalConfiguration();
                }

                List<Integer> workers = helper.getWorkerSession().getWorkers(GlobalConfiguration.WORKERTYPE_PROCESSABLE);

                Collections.sort(workers);

                Iterator<?> iter = workers.iterator();
                while (iter.hasNext()) {
                    Integer id = (Integer) iter.next();
                    displayWorkerStatus(id.intValue(), helper.getWorkerSession().getStatus(id.intValue()), complete);
                }
            } else {
                int id = helper.getWorkerId(args[1]);
                displayWorkerStatus(id, helper.getWorkerSession().getStatus(id), complete);
            }
        } catch (Exception e) {
            if (e instanceof IllegalCommandArgumentsException) {
                throw (IllegalCommandArgumentsException) e;
            }
            throw new UnexpectedCommandFailureException(e);
        }
        return 0;
    }
    
    private void displayWorkerStatus(int workerid, WorkerStatus status, boolean complete) {
        status.displayStatus(workerid, out, complete);
        out.println();
    }

    private void displayGlobalConfiguration() throws RemoteException, Exception {
        GlobalConfiguration gc = helper.getGlobalConfigurationSession().getGlobalConfiguration();
        out.println("The Global Configuration of Properties are :\n");

        if (!gc.getKeyEnumeration().hasMoreElements()) {
            out.println("  No properties exists in global configuration\n");
        }

        Enumeration<String> propertyKeys = gc.getKeyEnumeration();
        while (propertyKeys.hasMoreElements()) {
            String key = (String) propertyKeys.nextElement();
            out.println("  " + key + "=" + gc.getProperty(key) + "\n");
        }

        if (gc.getState().equals(GlobalConfiguration.STATE_INSYNC)) {
            out.println("  The global configuration is in sync with the database.\n");
        } else {
            out.println("  WARNING: The global configuratuon is out of sync with the database.\n");
        }

        out.println("\n");

    }
}
