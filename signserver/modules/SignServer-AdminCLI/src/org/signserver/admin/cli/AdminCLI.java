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
import org.apache.log4j.Logger;
import org.signserver.admin.cli.spi.AdminCommandFactory;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.InvalidWorkerIdException;

/**
 * Implements the SignServer command line interface.
 *
 * @version $Id$
 */
public class AdminCLI {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AdminCLI.class);

    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        int resultCode = 0;
        
        try {
            CommandLineInterface cli = new CommandLineInterface();
            cli.setFactoryClass(AdminCommandFactory.class);
            resultCode = cli.execute(args);
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
            resultCode = -2;
        } catch (IllegalCommandArgumentsException e) {
            System.out.println(e.getMessage());
            resultCode = -1;
        } catch (CommandFailureException e) {
            if (e.getCause() instanceof InvalidWorkerIdException) {
                System.out.println(e.getMessage());
                resultCode = -1;
            } else {
                System.out.println(e.getMessage());
                e.printStackTrace();
                resultCode = -2;
            }
        }
        System.exit(resultCode);
    }

}
