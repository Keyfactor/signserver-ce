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
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.WorkerStatus;

/**
 * Gets the current status of the given worker
 *
 * @version $Id$
 */
public class GetStatusCommand extends AbstractCommand {

    private AdminCommandHelper helper = new AdminCommandHelper();
    
    private static final String ERROR_MESSAGE = 
            "Usage: signserver getstatus <brief | detailed | complete> <workerId | workerName | all>\n"
                + "Example 1: signserver getstatus brief all\n"
                + "Example 2: signserver getstatus detailed all\n"
                + "Example 3: signserver getstatus complete all\n"
                + "Example 2: signserver getstatus brief 1\n"
                + "Example 4: signserver getstatus detailed 2\n"
                + "Example 5: signserver getstatus complete mySigner\n\n";
    
    private static final String INDENT1 = WorkerStatus.INDENT1;
    private static final String INDENT2 = WorkerStatus.INDENT2;

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
        
        out.print("Server: ");
        try {
            out.println(helper.getGlobalConfigurationSession().getGlobalConfiguration().getAppVersion());
        } catch (RemoteException ex) {
            Logger.getLogger(GetStatusCommand.class.getName()).log(Level.SEVERE, null, ex);
        }
        out.println();
        
        try {
            String mode = args[0];

            boolean allSigners = false;
            if (args[1].equalsIgnoreCase("all")) {
                allSigners = true;
            }

            if (!(mode.equalsIgnoreCase("complete") || mode.equalsIgnoreCase("brief") || mode.equalsIgnoreCase("detailed"))) {
                throw new IllegalCommandArgumentsException(ERROR_MESSAGE);
            }

            boolean complete = mode.equalsIgnoreCase("complete");
            boolean detailed = mode.equalsIgnoreCase("detailed");

            if (allSigners) {
                if (complete) {
                    displayGlobalConfiguration();
                }

                List<Integer> workers = helper.getWorkerSession().getWorkers(GlobalConfiguration.WORKERTYPE_ALL);
                Collections.sort(workers);
                for (Integer id : workers) {
                    displayStatus(id, detailed, complete);
                }
            } else {
                int id = helper.getWorkerId(args[1]);
                displayStatus(id, detailed, complete);
            }
        } catch (Exception e) {
            if (e instanceof IllegalCommandArgumentsException) {
                throw (IllegalCommandArgumentsException) e;
            }
            throw new UnexpectedCommandFailureException(e);
        }
        return 0;
    }

    private void displayGlobalConfiguration() throws RemoteException, Exception {
        GlobalConfiguration gc = helper.getGlobalConfigurationSession().getGlobalConfiguration();
        out.println("Global configuration:\n");

        if (!gc.getKeyEnumeration().hasMoreElements()) {
            out.print(INDENT1);
            out.println("No properties exists in global configuration\n");
        }

        out.println(INDENT1 + "Properties:");
        Enumeration<String> propertyKeys = gc.getKeyEnumeration();
        while (propertyKeys.hasMoreElements()) {
            String key = (String) propertyKeys.nextElement();
            out.print(INDENT1 + INDENT2);
            out.print(key);
            out.print("=");
            out.println(indented(gc.getProperty(key)));
            out.println();
        }

        out.print(INDENT1);
        if (gc.getState().equals(GlobalConfiguration.STATE_INSYNC)) {
            out.println("The global configuration is in sync with the database.");
        } else {
            out.println("WARNING: The global configuratuon is out of sync with the database.");
        }
        out.println();
    }
    
    private void displayStatus(Integer id, boolean detailed, boolean complete) {
        try {
            WorkerStatus status = helper.getWorkerSession().getStatus(id.intValue());
            out.println(String.format("[%-7s] %s %d, %s:", status.isOK() == null ? "ACTIVE" : "OFFLINE", status.getType(), id, status.getActiveSignerConfig().getProperty("NAME", "")));
            status.displayStatus(id, out, complete || detailed);
            if (complete) {
                displayWorkerConfig(status.getActiveSignerConfig().getProperties());
            } 
        } catch (InvalidWorkerIdException ex) {
            out.println("Unable to get status for worker " + id + ": " + ex.getMessage());
        } catch (RemoteException ex) {
            out.println("Unable to get status for worker " + id + ": " + ex.getMessage());
        }
    }

    private void displayWorkerConfig(Properties properties) {
        out.print(INDENT1);
        out.println("Active properties:");
        if(properties.size() == 0){
            out.print(INDENT1 + INDENT2);
            out.println("(No properties exists in active configuration)");
        }
        List<String> keys = new LinkedList(properties.stringPropertyNames());
        Collections.sort(keys);
        for (String key : keys) {
            out.print(INDENT1 + INDENT2);
            out.print(key);
            out.print("=");
            out.println(indented(properties.getProperty(key)));
            out.println();
        }
    }
    
    private static String indented(String original) {
        return original.replace("\n", "\n" + INDENT1 + INDENT2 + INDENT2);
    }
}
