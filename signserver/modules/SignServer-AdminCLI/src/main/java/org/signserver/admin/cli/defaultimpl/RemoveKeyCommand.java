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

import java.util.Collection;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.ejbca.ui.cli.util.ConsolePasswordReader;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.KeyTestResult;
import org.signserver.common.SignServerException;

/**
 * Command used to remove keys associated with a Crypto Token.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class RemoveKeyCommand extends AbstractAdminCommand {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(RemoveKeyCommand.class);

    /** The command line options. */
    private static final Options OPTIONS;

    private static final String USAGE = "Usage: signserver removekey <worker id | worker name> -alias <key alias> [-noask]\n"
            + "Example: signserver removekey 71 signerKey001";
    
    private static final String ALIAS = "alias";
    private static final String NOASK = "noask";

    private String alias;
    private boolean noAsk;
    
    static {
        OPTIONS = new Options();
        OPTIONS.addOption(ALIAS, true, "Alias of the key in the token to remove");
        OPTIONS.addOption(NOASK, true, "Removes the specified key without asking for confirmation");
    }

    @Override
    public String getDescription() {
        return "Warning the command will attempt to permanently destroy the specified key if supported by the token.";
    }

    @Override
    public String getUsages() {
        return USAGE;
    }
    
    /**
     * Reads all the options from the command line.
     *
     * @param line The command line to read from
     */
    private void parseCommandLine(final CommandLine line) {
        alias = line.getOptionValue(ALIAS, null);
        if (line.hasOption(NOASK)) {
            noAsk = Boolean.parseBoolean(line.getOptionValue(NOASK, Boolean.FALSE.toString()));
        }
    }

    /**
     * Checks that all mandadory options are given.
     */
    private void validateOptions() throws IllegalCommandArgumentsException {
        if (alias == null) {
            throw new IllegalCommandArgumentsException("Missing argument: -" + ALIAS);
        }
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        try {
            // Parse the command line
            parseCommandLine(new GnuParser().parse(OPTIONS, args));
        } catch (ParseException ex) {
            throw new IllegalArgumentException(ex.getLocalizedMessage(), ex);
        }
        validateOptions();
        
        if (args.length < 1) {
            throw new IllegalCommandArgumentsException(USAGE);
        }
        
        try {
            int signerId = getWorkerId(args[0]);
            checkThatWorkerIsProcessable(signerId);
        
            final boolean proceed;
            if (noAsk) {
                proceed = true;
            } else {
                getOutputStream().println("WARNING: Will attempt to permantently remove the following key:");
                getOutputStream().println(alias);
                getOutputStream().println();
                getOutputStream().println("Note: the key might be used by multiple workers.");
                getOutputStream().println("Are you sure you want to try to destroy the key? [YES/no] ");
                final String answer = System.console().readLine();
                proceed = "YES".equals(answer);
            }
                
            if (proceed) {
                final boolean result = getWorkerSession().removeKey(signerId, alias);
                getOutputStream().println("Key removal returned: " + result);
                return result ? CommandLineInterface.RETURN_SUCCESS : CommandLineInterface.RETURN_ERROR;
            } else {
                getOutputStream().println("Aborted");
                return CommandLineInterface.RETURN_INVALID_ARGUMENTS;
            }

        } catch (CryptoTokenOfflineException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Crypto token offline: " + ex.getMessage(), ex);
            }
            getErrorStream().println(ex.getMessage());
            return CommandLineInterface.RETURN_ERROR;
        } catch (SignServerException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error: " + ex.getMessage(), ex);
            }
            getErrorStream().println(ex.getMessage());
            return CommandLineInterface.RETURN_ERROR;
        } catch (InvalidWorkerIdException ex) {
            getErrorStream().println(ex.getMessage());
            return CommandLineInterface.RETURN_ERROR;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
}
