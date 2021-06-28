/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.db.cli;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.db.cli.spi.DatabaseCommandFactory;

/**
 * Main class of the SignServer Database CLI application.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Main extends CommandLineInterface {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(Main.class);
    
    public Main() {
        super(DatabaseCommandFactory.class, getCLIProperties());
    }

    /**
     * @param args the command line arguments
     * @throws UnexpectedCommandFailureException on command failures
     */
    @SuppressWarnings("PMD.DoNotCallSystemExit") // Not an JEE app
    public static void main(String[] args) throws UnexpectedCommandFailureException {
        // Execute the CLI
        Main databaseCLI = new Main();
        System.exit(databaseCLI.execute(args));
    }
    
    private static Properties getCLIProperties() {
        Properties properties = new Properties();
        InputStream in = null; 
        try {
            in = Main.class.getResourceAsStream("/signserver_cli.properties");
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
