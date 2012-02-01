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
import org.apache.log4j.Logger;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.client.cli.spi.ClientCommandFactory;

/**
 * Main class for the Client CLI.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Main {

     /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(Main.class);

    /** No instances of this class. */
    private Main() { }
 
    /**
     * @param args the command line arguments
     */
    public static void main(final String[] args) {
        try {
            CommandLineInterface cli = new CommandLineInterface();
            cli.setFactoryClass(ClientCommandFactory.class);
            cli.execute(args);
        } catch (IllegalCommandArgumentsException ex) {
            LOG.error(ex.getMessage());
        } catch (CommandFailureException ex) {
            LOG.error(ex.getMessage());
        } catch (IOException ex) {
            LOG.error("Unexpected failure running the command", ex);
        }
    }

}
