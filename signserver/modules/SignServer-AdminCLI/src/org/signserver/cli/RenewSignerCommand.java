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
package org.signserver.cli;

import java.util.Properties;
import javax.ejb.EJBException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.log4j.Logger;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.module.renewal.common.RenewalWorkerProperties;

/**
 * Command used to renew a signer by calling a Renewal Worker which (optionally)
 * generates a new key and then sends a request to EJBCA for a certificate
 * and installs it to SignServer.
 *
 * @version $Id$
 */
public class RenewSignerCommand extends BaseCommand {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(RenewSignerCommand.class);

    public static final String RENEWALWORKER = "renewalworker";

    /** The command line options. */
    private static final Options OPTIONS;

    private static final String USAGE =
        "Usage: signserver renewsigner <worker name> -renewalworker <worker name>\n"
        + "Example 1: signserver renewsigner signer71 -renewalworker RenewalWorker1\n";
    
    static {
        OPTIONS = new Options();
        OPTIONS.addOption(RENEWALWORKER, true, 
                "The worker which performs the renewal");
    }

    private String renewalWorker;

    /**
     * Creates a new instance of GenerateKeyCommand.
     * @param args command line arguments
     */
    public RenewSignerCommand(String[] args) {
        super(args);
        try {
            // Parse the command line
            parseCommandLine(new GnuParser().parse(OPTIONS, args));
        } catch (ParseException ex) {
            throw new IllegalArgumentException(ex.getLocalizedMessage(), ex);
        }
        validateOptions();
    }

    /**
     * Reads all the options from the command line.
     *
     * @param line The command line to read from
     */
    private void parseCommandLine(final CommandLine line) {
        if (line.hasOption(RENEWALWORKER)) {
            renewalWorker = line.getOptionValue(RENEWALWORKER, null);
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

    /**
     * Runs the command
     *
     * @param hostname
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute(String hostname) throws IllegalAdminCommandException,
            ErrorAdminCommandException {
        if (args.length < 2) {
            throw new IllegalAdminCommandException(USAGE);
        }
        try {

            String workerName = args[1];
            checkThatWorkerIsProcessable(getWorkerId(workerName, hostname), hostname);

            final Properties requestProperties = new Properties();
            requestProperties.setProperty(
                    RenewalWorkerProperties.REQUEST_WORKER, workerName);
//                    requestProperties.setProperty(
//                            RenewalWorkerProperties.REQUEST_RENEWKEY,
//                            RenewalWorkerProperties.REQUEST_RENEWKEY_TRUE);
            final GenericPropertiesRequest request
                    = new GenericPropertiesRequest(requestProperties);

            final GenericPropertiesResponse response =
                            (GenericPropertiesResponse)
                            getCommonAdminInterface(hostname).processRequest(
                            getWorkerId(renewalWorker, hostname), request);

            final Properties responseProperties =
                    response.getProperties();

            if (RenewalWorkerProperties.RESPONSE_RESULT_OK.equals(
                    responseProperties.getProperty(
                        RenewalWorkerProperties.RESPONSE_RESULT))) {
                LOG.info("Renewed successfully");
            } else {
                LOG.error("Renewal failed: " + responseProperties.getProperty(
                        RenewalWorkerProperties.RESPONSE_MESSAGE));
            }


        } catch (IllegalAdminCommandException e) {
            throw e;
        } catch (EJBException eJBException) {
            if (eJBException.getCausedByException()
                    instanceof IllegalArgumentException) {
                System.err.println(eJBException.getMessage());
            } else {
                throw new ErrorAdminCommandException(eJBException);
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    public int getCommandType() {
        return TYPE_EXECUTEONALLNODES;
    }
    // execute
}
