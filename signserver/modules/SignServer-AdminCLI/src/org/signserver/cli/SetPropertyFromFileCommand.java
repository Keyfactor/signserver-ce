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

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.RemoteException;

import org.ejbca.util.Base64;
import org.signserver.common.GlobalConfiguration;

/**
 * Sets a property for a given workerid with byte data from file set as a BASE94 encoded string
 *
 * @version $Id$
 */
public class SetPropertyFromFileCommand extends BaseCommand {

    /**
     * Creates a new instance of SetPropertyFromFileCommand
     *
     * @param args command line arguments
     */
    public SetPropertyFromFileCommand(String[] args) {
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
            throw new IllegalAdminCommandException("Usage: signserver setpropertyfromfile <-host hostname (optional)> <signerid | signerName | global | node> <propertykey> <filename>\n"
                    + "Example 1: signserver setproperty 1 defaultKey myfile.dat\n"
                    + "Example 2: signserver setproperty mySigner defaultKey myfile.dat\n"
                    + "Example 3: signserver setproperty global WORKER6.CLASSPATH myfile.dat\n"
                    + "Example 4: signserver setproperty -host node3.someorg.com node SOMENODEDATA myfile.dat\n\n");
        }
        try {

            String propertykey = args[2];

            String data = readDataFromFile(args[3]);

            String workerid = args[1];

            if (workerid.substring(0, 1).matches("\\d")) {
                setWorkerProperty(Integer.parseInt(workerid), hostname, propertykey, data);
            } else {
                if (workerid.trim().equalsIgnoreCase("GLOBAL")) {
                    setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, hostname, propertykey, data);
                } else {
                    if (workerid.trim().equalsIgnoreCase("NODE")) {
                        setGlobalProperty(GlobalConfiguration.SCOPE_NODE, hostname, propertykey, data);

                    } else {
                        // named worker is requested
                        int id = getCommonAdminInterface(hostname).getWorkerId(workerid);
                        if (id == 0) {
                            throw new IllegalAdminCommandException("Error: No worker with the given name could be found");
                        }
                        setWorkerProperty(id, hostname, propertykey, data);
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

    private String readDataFromFile(String filename) throws IllegalAdminCommandException {
        String retval = null;
        try {
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(filename));
            byte[] buffer = new byte[bis.available()];
            bis.read(buffer);
            retval = new String(Base64.encode(buffer));
        } catch (FileNotFoundException e) {
            throw new IllegalAdminCommandException("Error : File " + filename + " wasn't found or readable.");
        } catch (IOException e) {
            throw new IllegalAdminCommandException("Error reading file " + filename + ": " + e.getMessage());
        }
        return retval;
    }

    private void setGlobalProperty(String scope, String hostname, String key, String value) throws RemoteException, Exception {
        this.getOutputStream().println("Setting the global property " + key + " with data from file with scope " + scope + "\n");
        this.getOutputStream().println("See current configuration with the getconfig command, activate it with the reload command");

        getCommonAdminInterface(hostname).setGlobalProperty(scope, key, value);
    }

    // execute
    public int getCommandType() {
        return TYPE_EXECUTEONMASTER;
    }

    private void setWorkerProperty(int workerId, String hostname, String propertykey, String propertyvalue) throws RemoteException, Exception {
        this.getOutputStream().println("Setting the property " + propertykey + " to data from file for worker " + workerId + "\n");
        this.getOutputStream().println("See current configuration with the getconfig command, activate it with the reload command");

        getCommonAdminInterface(hostname).setWorkerProperty(workerId, propertykey, propertyvalue);
    }
}
