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
package org.signserver.client.cli;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.client.cli.spi.ClientCommandFactory;

/**
 * Main class for the Client CLI.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ClientCLI extends CommandLineInterface {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ClientCLI.class);

    public ClientCLI() {
        super(ClientCommandFactory.class, getCLIProperties());
    }
 
    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) throws UnexpectedCommandFailureException {
        ClientCLI adminCLI = new ClientCLI();
        System.exit(adminCLI.execute(args));
    }
    
    private static Properties getCLIProperties() {
        Properties properties = new Properties();
        InputStream in = null; 
        try {
            in = ClientCLI.class.getResourceAsStream("/signserver_cli.properties");
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

}
