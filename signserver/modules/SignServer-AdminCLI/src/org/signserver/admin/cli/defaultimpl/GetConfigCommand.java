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
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;

/**
 * Gets the current configuration of the given signer, this might not be the same as
 * the active configuration.
 *
 * @version $Id$
 */
public class GetConfigCommand extends AbstractCommand {

    private AdminCommandHelper helper = new AdminCommandHelper();

    @Override
    public String getDescription() {
        return "Get the configuration either global or for a worker";
    }
    
    @Override
    public int execute(String[] args) throws IllegalCommandArgumentsException, CommandFailureException {
        
        if (args.length != 1) {
            throw new IllegalCommandArgumentsException("Usage: signserver getconfig <workerid | workerName | global> \n"
                    + "Example 1 : signserver getconfig 1 \n"
                    + "Example 2 : signserver getconfig mySigner \n"
                    + "Example 3 : signserver getconfig global \n\n");
        }
        try {
            String workerid = args[0];

            if (workerid.substring(0, 1).matches("\\d")) {
                displayWorkerConfig(Integer.parseInt(workerid));
            } else {
                if (workerid.trim().equalsIgnoreCase("GLOBAL")) {
                    // global configuration is requested
                    displayGlobalConfiguration();

                } else {
                    // named worker is requested
                    int id = helper.getWorkerSession().getWorkerId(workerid);
                    if (id == 0) {
                        throw new IllegalAdminCommandException("Error: No worker with the given name could be found");
                    }
                    displayWorkerConfig(id);
                }
            }
        } catch (IllegalCommandArgumentsException e) {
            throw e;
        } catch (Exception e) {
            throw new CommandFailureException(e);
        }
        return 0;
    }

    private void displayGlobalConfiguration() throws RemoteException, Exception {
        GlobalConfiguration gc = helper.getGlobalConfigurationSession().getGlobalConfiguration();
        Enumeration<String> en = gc.getKeyEnumeration();
        out.println(" This node has the following Global Configuration:");
        while (en.hasMoreElements()) {
            String key = en.nextElement();
            out.println("   Key : " + key + " Value : " + gc.getProperty(key));
        }
    }

    private void displayWorkerConfig(int workerId) throws RemoteException, Exception {
        WorkerConfig config = helper.getWorkerSession().getCurrentWorkerConfig(workerId);

        out.println(
                "OBSERVE that this command displays the current configuration which\n"
                + "doesn't have to be the same as the active configuration.\n"
                + "Configurations are activated with the reload command. \n\n"
                + "The current configuration of worker with id : " + workerId + " is :");


        if (config.getProperties().size() == 0) {
            out.println("  No properties exists in the current configuration\n");
        }

        Enumeration<?> propertyKeys = config.getProperties().keys();
        while (propertyKeys.hasMoreElements()) {
            String key = (String) propertyKeys.nextElement();
            out.println("  " + key + "=" + config.getProperties().getProperty(key) + "\n");
        }

        ProcessableConfig pConfig = new ProcessableConfig(config);
        if (pConfig.getSignerCertificate() != null) {
            out.println(" The current configuration use the following signer certificate : \n");
            WorkerStatus.printCert(pConfig.getSignerCertificate(), out);
        } else {
            out.println(" Either this isn't a Signer or no Signer Certificate have been uploaded to it.\n");
        }
    }
}
