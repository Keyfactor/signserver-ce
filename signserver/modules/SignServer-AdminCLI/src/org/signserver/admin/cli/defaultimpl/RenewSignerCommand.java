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

import java.util.Properties;
import javax.ejb.EJBException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.common.GenericPropertiesRequest;
import org.signserver.common.GenericPropertiesResponse;
import org.signserver.common.RequestContext;
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
    
    /** The command line options. */
    private static final Options OPTIONS;
    
    private static final String USAGE =
            "Usage: signserver renewsigner <worker name> -renewalworker <worker name>\n"
            + "Example 1: signserver renewsigner signer71 -renewalworker RenewalWorker1\n";

    private String renewalWorker;
    
    static {
        OPTIONS = new Options();
        OPTIONS.addOption(RENEWALWORKER, true,
                "The worker which performs the renewal");
    }

    @Override
    public String getDescription() {
        return "Renews a signer by calling a Renewal Worker";
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

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException {
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

            String workerName = args[1];
            checkThatWorkerIsProcessable(getWorkerId(workerName));

            final Properties requestProperties = new Properties();
            requestProperties.setProperty(
                    RenewalWorkerProperties.REQUEST_WORKER, workerName);
//                    requestProperties.setProperty(
//                            RenewalWorkerProperties.REQUEST_RENEWKEY,
//                            RenewalWorkerProperties.REQUEST_RENEWKEY_TRUE);
            final GenericPropertiesRequest request = new GenericPropertiesRequest(requestProperties);

            final GenericPropertiesResponse response =
                    (GenericPropertiesResponse) getWorkerSession().process(
                    getWorkerId(renewalWorker), request, new RequestContext(true));

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
                throw new CommandFailureException(eJBException);
            }
        } catch(IllegalCommandArgumentsException ex) {
            throw ex;
        } catch (Exception e) {
            throw new CommandFailureException(e);
        }
    }

}
