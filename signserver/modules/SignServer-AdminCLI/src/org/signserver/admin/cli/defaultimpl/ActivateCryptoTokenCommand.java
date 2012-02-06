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

import java.io.IOException;
import java.rmi.RemoteException;
import org.apache.log4j.Logger;
import org.ejbca.ui.cli.util.ConsolePasswordReader;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.SignerStatus;

/**
 * Command used to activate a Crypto Token
 *
 * @version $Id$
 */
public class ActivateCryptoTokenCommand extends AbstractAdminCommand {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ActivateCryptoTokenCommand.class);
    
    private static final String HELP = 
            "Usage: signserver activatesigntoken <worker id | worker name> <authentication code> \n"
            + "Leaving out authorization code will prompt for it.\n\n"
            + "Example 1 : signserver activatecryptotoken 1 123456 \n"
            + "Example 2 : signserver activatecryptotoken 1 \n"
            + "Example 3 : signserver activatecryptotoken mySigner 123456 \n\n";
    private static final String TRYING = "Trying to activate crypto token of worker with id : ";
    private static final String SUCCESS = "Activation of worker was successful\n\n";
    private static final String FAIL = "Activation of worker FAILED\n\n";
    

    @Override
    public String getDescription() {
        return "Activates a crypto token";
    }

    @Override
    public String getUsages() {
        return HELP;
    }

    /**
     * Runs the command
     *
     * @throws IllegalCommandArgumentsException Error in command args
     * @throws CommandFailureException Error running command
     */
    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length < 1) {
            throw new IllegalCommandArgumentsException("Missing arguments");
        }
        
        try {
            int workerid = getWorkerId(args[0]);
            checkThatWorkerIsProcessable(workerid);
            String authCode;
            if (args.length > 1) {
                authCode = args[1];
            } else {
                getOutputStream().print("Enter authorization code: ");
                // Read the password, but mask it so we don't display it on the console
                ConsolePasswordReader r = new ConsolePasswordReader();
                authCode = String.valueOf(r.readPassword());
            }

            this.getOutputStream().println(TRYING + workerid + "\n");
            this.getWorkerSession().activateSigner(workerid, authCode);

            boolean active = ((SignerStatus) getWorkerSession().getStatus(workerid)).getTokenStatus() == SignerStatus.STATUS_ACTIVE;
            
            if (active) {
                this.getOutputStream().println(SUCCESS);
            } else {
                this.getOutputStream().println(FAIL);
            }
            return 0;
        } catch (InvalidWorkerIdException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        } catch (RemoteException ex) {
            throw new UnexpectedCommandFailureException(ex);
        } catch (IOException ex) {
            throw new UnexpectedCommandFailureException(ex);
        } catch (CryptoTokenAuthenticationFailureException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Crypto token authentication failed", ex);
            }
            throw new CommandFailureException("Crypto token authentication failed: " + ex.getLocalizedMessage());
        } catch (CryptoTokenOfflineException ex) {
            throw new CommandFailureException("Crypto token is offline: " + ex.getLocalizedMessage());
        }
    }

}
