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

import javax.ejb.EJBException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.ejbca.ui.cli.util.ConsolePasswordReader;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;

/**
 * Command used to generate a new signing key.
 *
 * @version $Id$
 */
public class GenerateKeyCommand extends AbstractAdminCommand {

    /** Logger for this class. */
    private final Logger LOG = getLogger();
    
    public static final String KEYALG = "keyalg";
    public static final String KEYSPEC = "keyspec";
    public static final String ALIAS = "alias";
    public static final String AUTHCODE = "authcode";
    
    /** The command line options. */
    private static final Options OPTIONS;
    private static final String USAGE =
            "Usage: signserver generatekey <worker id | worker name> [-keyalg <key algorithm> -keyspec <key spec> -alias <alias>]\n"
            + "Leaving out alias will use the value in property DEFAULTKEY+1.\n"
            + "Leaving out keyalg will use the value in property KEYALG.\n"
            + "Leaving out keyspec will use the value in property KEYSPEC.\n"
            + "Leaving out authcode will prompt for it.\n"
            + "Example 1: signserver generatekey 71\n"
            + "Example 2: signserver generatekey 71 -keyalg RSA -keyspec 2048\n"
            + "Example 3: signserver generatekey 71 -keyalg RSA -keyspec 2048 -alias signKey2\n"
            + "Example 4: signserver generatekey 71 -keyalg ECDSA -keyspec secp256r1 -alias signKey2";

    static {
        OPTIONS = new Options();
        OPTIONS.addOption(KEYALG, true, "Key algorithm");
        OPTIONS.addOption(KEYSPEC, true, "Key specification");
        OPTIONS.addOption(ALIAS, true, "Key alias/name");
        OPTIONS.addOption(AUTHCODE, true, "Authentication code");
    }
    
    private String keyAlg;
    private String keySpec;
    private String alias;
    private char[] authCode;

    @Override
    public String getDescription() {
        return "Generates a new signing key-pair";
    }

    /**
     * Reads all the options from the command line.
     *
     * @param line The command line to read from
     */
    private void parseCommandLine(final CommandLine line) {
        if (line.hasOption(KEYALG)) {
            keyAlg = line.getOptionValue(KEYALG, null);
        }
        if (line.hasOption(KEYSPEC)) {
            keySpec = line.getOptionValue(KEYSPEC, null);
        }
        if (line.hasOption(ALIAS)) {
            alias = line.getOptionValue(ALIAS, null);
        }
        if (line.hasOption(AUTHCODE)) {
            authCode = line.getOptionValue(AUTHCODE, null).toCharArray();
        }
    }

    /**
     * Checks that all mandadory options are given.
     */
    private void validateOptions() {
        // No mandatory options.
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException {
        if (args.length < 1) {
            throw new IllegalCommandArgumentsException(USAGE);
        }
        try {
            try {
                // Parse the command line
                parseCommandLine(new GnuParser().parse(OPTIONS, args));
            } catch (ParseException ex) {
                throw new IllegalCommandArgumentsException(ex.getMessage());
            }
            validateOptions();

            if (authCode == null) {
                getOutputStream().print("Enter authorization code: ");
                // Read the password, but mask it so we don't display it on
                // the console
                final ConsolePasswordReader r = new ConsolePasswordReader();
                authCode = r.readPassword();
            }

            int signerId = getWorkerId(args[0]);
            checkThatWorkerIsProcessable(signerId);

            LOG.info("Requesting key generation...");

            String newAlias = getWorkerSession().generateSignerKey(
                    signerId, keyAlg, keySpec, alias, authCode);

            if (newAlias == null) {
                out.println("Could not generate key");
            } else {
                out.println("Created key : " + newAlias);
            }
            return 0;
        } catch(IllegalCommandArgumentsException ex) { 
            throw ex;
        } catch (EJBException eJBException) {
            if (eJBException.getCausedByException() instanceof IllegalArgumentException) {
                err.println(eJBException.getMessage());
                return -1;
            } else {
                throw new CommandFailureException(eJBException);
            }
        } catch (Exception e) {
            throw new CommandFailureException(e);
        } finally {
            authCode = null;
        }
    }
}
