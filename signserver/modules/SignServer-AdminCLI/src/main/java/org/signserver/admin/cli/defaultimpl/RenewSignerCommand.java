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

import java.io.Console;
import java.util.Properties;
import javax.ejb.EJBException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.WorkerIdentifier;
import org.signserver.module.renewal.common.RenewalWorkerProperties;

/**
 * Command used to renew a signer by calling a Renewal Worker which (optionally)
 * generates a new key and then sends a request to EJBCA for a certificate
 * and installs it to SignServer.
 *
 * @version $Id$
 */
public class RenewSignerCommand extends AbstractAdminCommand {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(RenewSignerCommand.class);
    
    public static final String RENEWALWORKER = "renewalworker";
    public static final String AUTHCODE = "authcode";
    public static final String AUTHPROMPT = "authprompt";

    /** The command line options. */
    private static final Options OPTIONS;
    
    private static final String USAGE =
            "Usage: signserver renewsigner <worker name> -renewalworker <worker name> [-authcode <authentication code>|-authprompt]\n"
            + "Example 1: signserver renewsigner signer71 -renewalworker RenewalWorker1\n"
            + "Example 2: signserver renewsigner signer71 -renewalworker RenewalWorker1 -authcode foo123\n"
            + "Example 3: signserver renewsigner signer71 -renewalworker RenewalWorker1 -authprompt\n";

    private WorkerIdentifier renewalWorker;
    private String authCode;
    private boolean promptForAuthCode;
    
    static {
        OPTIONS = new Options();
        OPTIONS.addOption(RENEWALWORKER, true,
                "The worker which performs the renewal");
        OPTIONS.addOption(AUTHCODE, true,
                "The authentication code to activate the signer to renew");
        OPTIONS.addOption(AUTHPROMPT, false,
                "Prompt for authentication code. This option can not be used together with -authcode");
    }

    @Override
    public String getDescription() {
        return "Renews a signer by calling a Renewal Worker";
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
        if (line.hasOption(RENEWALWORKER)) {
            renewalWorker = new WorkerIdentifier(line.getOptionValue(RENEWALWORKER, null));
        }
        if (line.hasOption(AUTHCODE)) {
            authCode = line.getOptionValue(AUTHCODE, null);
        }
        
        if (line.hasOption(AUTHPROMPT)) {
            promptForAuthCode = true;
        }
    }

    /**
     * Checks that all mandatory options are given.
     */
    private void validateOptions() {
        if (renewalWorker == null) {
            LOG.error("Missing property: -renawalworker");
            LOG.info(USAGE);
            System.exit(1);
        }
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        try {
            // Parse the command line
            parseCommandLine(new GnuParser().parse(OPTIONS, args));
        } catch (ParseException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        }
        validateOptions();
        
        if (args.length < 2) {
            throw new IllegalCommandArgumentsException(USAGE);
        }
        try {
            
            if (authCode != null && promptForAuthCode) {
                throw new IllegalCommandArgumentsException("You can not specify both -authcode and -authprompt at the same time");
            }
            
            if (promptForAuthCode) {
                getOutputStream().print("Enter authorization code: ");
                // Read the password, but mask it so we don't display it on the console
                final Console console = System.console();
                
                if (console != null) {
                    authCode = String.valueOf(console.readPassword());
                } else {
                    throw new CommandFailureException("Unable to read password");
                }
            }

            String workerName = args[0];
            checkThatWorkerIsProcessable(getWorkerId(workerName));

            final Properties requestProperties = new Properties();
            requestProperties.setProperty(
                    RenewalWorkerProperties.REQUEST_WORKER, workerName);
            requestProperties.setProperty(
                            RenewalWorkerProperties.REQUEST_AUTHCODE,
                            String.valueOf(authCode));
//                    requestProperties.setProperty(
//                            RenewalWorkerProperties.REQUEST_RENEWKEY,
//                            RenewalWorkerProperties.REQUEST_RENEWKEY_TRUE);
            final GenericPropertiesRequest request = new GenericPropertiesRequest(requestProperties);

            final GenericPropertiesResponse response =
                    (GenericPropertiesResponse) getProcessSession().process(
                    renewalWorker, request, new RemoteRequestContext());

            final Properties responseProperties =
                    response.getProperties();

            if (RenewalWorkerProperties.RESPONSE_RESULT_OK.equals(
                    responseProperties.getProperty(
                    RenewalWorkerProperties.RESPONSE_RESULT))) {
                out.println("Renewed successfully");
                return 0;
            } else {
                err.println("Renewal failed: " + responseProperties.getProperty(
                        RenewalWorkerProperties.RESPONSE_MESSAGE));
                return -2;
            }
        } catch (EJBException eJBException) {
            if (eJBException.getCausedByException() instanceof IllegalArgumentException) {
                err.println(eJBException.getMessage());
                return -2;
            } else {
                throw new UnexpectedCommandFailureException(eJBException);
            }
        } catch(IllegalCommandArgumentsException ex) {
            throw ex;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }

}
