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

import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.WorkerIdentifier;

/**
 * Command used to deactivate a Crypto Token
 *
 * @version $Id$
 */
public class DeactivateCryptoTokenCommand extends AbstractAdminCommand {

    private static final String HELP = 
            "Usage: signserver deactivatecryptotoken <worker id | worker name> \n"
            + "Example: signserver deactivatecryptotoken 1 \n"
            + "Example 2 : signserver deactivatecryptotoken mySigner \n\n";
    private static final String TRYING = "Trying to deactivate crypto token of worker with id : ";
    private static final String SUCCESS = "Deactivation of worker was successful\n\n";

    @Override
    public String getDescription() {
        return "Deactivates a crypto token";
    }

    @Override
    public String getUsages() {
        return HELP;
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 1) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
        }
        try {
            WorkerIdentifier wi = WorkerIdentifier.createFromIdOrName(args[0]);

            this.getOutputStream().println(TRYING + wi + "\n");
            this.getWorkerSession().deactivateSigner(wi);
            this.getOutputStream().println(SUCCESS);
            return 0;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
}
