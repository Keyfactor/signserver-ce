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

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.RemoteException;
import org.ejbca.util.Base64;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.GlobalConfiguration;

/**
 * Sets a property for a given workerid with byte data from file set as a BASE94 encoded string
 *
 * @version $Id$
 */
public class SetPropertyFromFileCommand extends AbstractAdminCommand {

    @Override
    public String getDescription() {
        return "Sets a property for a given worker with byte data from file";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException {
        if (args.length != 3) {
            throw new IllegalCommandArgumentsException("Usage: signserver setpropertyfromfile <signerid | signerName | global | node> <propertykey> <filename>\n"
                    + "Example 1: signserver setproperty 1 defaultKey myfile.dat\n"
                    + "Example 2: signserver setproperty mySigner defaultKey myfile.dat\n"
                    + "Example 3: signserver setproperty global WORKER6.CLASSPATH myfile.dat\n"
                    + "Example 4: signserver setproperty -host node3.someorg.com node SOMENODEDATA myfile.dat\n\n");
        }
        try {

            String propertykey = args[1];
            String data = readDataFromFile(args[2]);
            String workerid = args[0];

            if (workerid.substring(0, 1).matches("\\d")) {
                setWorkerProperty(Integer.parseInt(workerid), propertykey, data);
            } else {
                if (workerid.trim().equalsIgnoreCase("GLOBAL")) {
                    setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, propertykey, data);
                } else {
                    if (workerid.trim().equalsIgnoreCase("NODE")) {
                        setGlobalProperty(GlobalConfiguration.SCOPE_NODE, propertykey, data);

                    } else {
                        // named worker is requested
                        int id = getWorkerSession().getWorkerId(workerid);
                        if (id == 0) {
                            throw new IllegalCommandArgumentsException("Error: No worker with the given name could be found");
                        }
                        setWorkerProperty(id, propertykey, data);
                    }

                }
            }

            this.getOutputStream().println("\n\n");
            return 0;
        } catch (IllegalCommandArgumentsException e) {
            throw e;
        } catch (Exception e) {
            throw new CommandFailureException(e);
        }
    }

    private String readDataFromFile(String filename) throws IllegalCommandArgumentsException {
        String retval = null;
        try {
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(filename));
            byte[] buffer = new byte[bis.available()];
            bis.read(buffer);
            retval = new String(Base64.encode(buffer));
        } catch (FileNotFoundException e) {
            throw new IllegalCommandArgumentsException("Error : File " + filename + " wasn't found or readable.");
        } catch (IOException e) {
            throw new IllegalCommandArgumentsException("Error reading file " + filename + ": " + e.getMessage());
        }
        return retval;
    }

    private void setGlobalProperty(String scope, String key, String value) throws RemoteException, Exception {
        this.getOutputStream().println("Setting the global property " + key + " with data from file with scope " + scope + "\n");
        this.getOutputStream().println("See current configuration with the getconfig command, activate it with the reload command");

        getGlobalConfigurationSession().setProperty(scope, key, value);
    }

    private void setWorkerProperty(int workerId, String propertykey, String propertyvalue) throws RemoteException, Exception {
        this.getOutputStream().println("Setting the property " + propertykey + " to data from file for worker " + workerId + "\n");
        this.getOutputStream().println("See current configuration with the getconfig command, activate it with the reload command");

        getWorkerSession().setWorkerProperty(workerId, propertykey, propertyvalue);
    }
}
