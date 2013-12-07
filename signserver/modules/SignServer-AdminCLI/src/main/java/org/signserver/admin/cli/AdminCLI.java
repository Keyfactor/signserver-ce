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
package org.signserver.admin.cli;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.admin.cli.spi.AdminCommandFactory;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.UnexpectedCommandFailureException;

/**
 * Implements the SignServer command line interface.
 *
 * @version $Id$
 */
public class AdminCLI extends CommandLineInterface {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AdminCLI.class);

    public AdminCLI() {
        super(AdminCommandFactory.class, getCLIProperties());
    }
        
    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) throws UnexpectedCommandFailureException {
        // Remove the legacy host parameter if existing
        String hostname = checkHostParameter(args);
        if (hostname != null) {
            args = removeHostParameters(args);
            System.err.println("Warning: The -host parameter is no longer supported and will be ignored!");
        }
        // Execute the CLI
        AdminCLI adminCLI = new AdminCLI();
        System.exit(adminCLI.execute(args));
    }
    
    private static Properties getCLIProperties() {
        Properties properties = new Properties();
        InputStream in = null; 
        try {
            in = AdminCLI.class.getResourceAsStream("/signserver_cli.properties");
            if (in != null) {
                properties.load(in);
            }
        } catch (IOException ex) {
            LOG.error("Could not load configuration: " + ex.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOG.error("Failed to close configuration", ex);
                }
            }
        }
        return properties;
    }
    
    /**
     * Method that checks if a '-host host' parameter exists 
     * and return the given hostname.
     * @return hostname or null if host param didn't exist
     */
    private static String checkHostParameter(String[] args) {
        String retval = null;

        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equalsIgnoreCase("-host")) {
                retval = args[i + 1];
                break;
            }
        }

        return retval;
    }

    /**
     * Method that checks if a '-host host' parameter exist and removes the parameters
     * and returns a new args array
     * @return a args arrray with -host paramter removed
     */
    private static String[] removeHostParameters(String[] args) {
        String[] retval = null;
        boolean found = false;
        int index = 0;
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equalsIgnoreCase("-host")) {
                index = i;
                found = true;
                break;
            }
        }

        if (found) {
            String newargs[] = new String[args.length - 2];
            for (int i = 0; i < args.length; i++) {
                if (i < index) {
                    newargs[i] = args[i];
                }
                if (i > index + 1) {
                    newargs[i - 2] = args[i];
                }
            }
            retval = newargs;
        }
        return retval;
    }

}
