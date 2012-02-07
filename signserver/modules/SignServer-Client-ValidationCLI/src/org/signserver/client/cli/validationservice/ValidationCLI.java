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
package org.signserver.client.cli.validationservice;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.client.cli.spi.ClientCommandFactory;

/**
 * Main class for the Validation CLI in case anyone wants to run this standalone 
 * (ie for debugging).
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ValidationCLI extends CommandLineInterface {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ValidationCLI.class);

    public ValidationCLI() {
        super(ClientCommandFactory.class, getCLIProperties());
    }
 
    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) throws UnexpectedCommandFailureException {
        ValidationCLI adminCLI = new ValidationCLI();
        System.exit(adminCLI.execute(args));
    }
    
    private static Properties getCLIProperties() {
        Properties properties = new Properties();
        InputStream in = null; 
        try {
            in = ValidationCLI.class.getResourceAsStream("/signserver_cli.properties");
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
