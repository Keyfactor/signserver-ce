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

import java.rmi.RemoteException;
import java.util.Arrays;
import java.util.Collection;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;
import org.signserver.common.WorkerConfig;
import org.signserver.common.util.PropertiesConstants;

/**
 * Command for adding, removing and listing a worker's client authorization
 * rules.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ClientsAuthorizationCommand extends AbstractAdminCommand {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ClientsAuthorizationCommand.class);

    public static final String ADD = "add";
    public static final String REMOVE = "remove";
    public static final String LIST = "list";
    public static final String WORKER = "worker";
    public static final String MATCH_SUBJECT_WITH_TYPE = "matchSubjectWithType";
    public static final String MATCH_SUBJECT_WITH_VALUE = "matchSubjectWithValue";
    public static final String MATCH_ISSUER_WITH_VALUE = "matchIssuerWithValue";
    public static final String DESCRIPTION = "description";
    
    /** The command line options. */
    private static final Options OPTIONS;
    
    static {
        OPTIONS = new Options();
        OPTIONS.addOption(ADD, false, "Add a new client authorization rule");
        OPTIONS.addOption(REMOVE, false, "Remove a client authorization rule");
        OPTIONS.addOption(LIST, false, "List all client authorization rules");

        OPTIONS.addOption(WORKER, true, "Worker name or ID");
        OPTIONS.addOption(MATCH_SUBJECT_WITH_TYPE, true, "Match subject with type");
        OPTIONS.addOption(MATCH_SUBJECT_WITH_VALUE, true, "Match subject with value");
        OPTIONS.addOption(MATCH_ISSUER_WITH_VALUE, true, "Match issuer with value");
        OPTIONS.addOption(DESCRIPTION, true, "A textual representation");
    }

    private String operation;
    private String worker;
    private MatchSubjectWithType matchSubjectWithType;
    private String matchSubjectWithValue;
    private String matchIssuerWithValue;
    private String description;
    
    @Override
    public String getDescription() {
        return "Authorizes clients";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver clients -worker <worker name or ID> <-add/-remove/list> -matchSubjectWithType <MATCH_TYPE> -matchSubjectWithValue <value> -matchIssuerWithValue <issuer DN> [-description <textual description>]\n"
                    + "Example 1: clients -worker CMSSigner -list\n"
                    + "Example 2: clients -worker CMSSigner -add -matchSubjectWithType SUBJECT_RDN_CN -matchSubjectWithValue \"Client One\" -matchIssuerWithValue \"CN=AdminCA1, C=SE\" -description \"my rule\"\n\n";
    }
    
    /**
     * Reads all the options from the command line.
     *
     * @param line The command line to read from
     */
    private void parseCommandLine(final CommandLine line)
        throws IllegalCommandArgumentsException {
        
        worker = line.getOptionValue(WORKER, null);

        int operations = 0;
        if (line.hasOption(ADD)) {
            operation = ADD;
            operations++;
        }
        if (line.hasOption(REMOVE)) {
            operation = REMOVE;
            operations++;
        }
        if (line.hasOption(LIST)) {
            operation = LIST;
            operations++;
        }
        if (operations != 1) {
            throw new IllegalCommandArgumentsException("Please specify one and only one of -add, -remove or -list");
        }
        
        final String matchSubjectWithTypeString = line.getOptionValue(MATCH_SUBJECT_WITH_TYPE, null);
        if (matchSubjectWithTypeString != null) {
            try {
                matchSubjectWithType = MatchSubjectWithType.valueOf(matchSubjectWithTypeString);
            } catch (IllegalArgumentException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unknown matchSubjectWithType: " + ex.getMessage());
                }
                throw new IllegalCommandArgumentsException("Unknown " + MATCH_SUBJECT_WITH_TYPE + " value provided. Possible values are: " + Arrays.toString(MatchSubjectWithType.values()));
            }
        }
        
        matchSubjectWithValue = line.getOptionValue(MATCH_SUBJECT_WITH_VALUE, null);
        matchIssuerWithValue = line.getOptionValue(MATCH_ISSUER_WITH_VALUE, null);
        description = line.getOptionValue(DESCRIPTION, null);
    }

    /**
     * Checks that all mandatory options are given.
     */
    private void validateOptions() throws IllegalCommandArgumentsException {
        if (worker == null) {
            throw new IllegalCommandArgumentsException("Missing -worker");
        }
        
        switch (operation) {
            case ADD:
            case REMOVE: {
                if (matchSubjectWithType == null) {
                    throw new IllegalCommandArgumentsException("Missing -matchSubjectWithType");
                }
                if (matchSubjectWithValue == null) {
                    throw new IllegalCommandArgumentsException("Missing -matchSubjectWithValue");
                }
                if (matchIssuerWithValue == null) {
                    throw new IllegalCommandArgumentsException("Missing -matchIssuerWithValue");
                }
            }
        }
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        final CommandLine line;
        try {
            // Parse the command line
            line = new GnuParser().parse(OPTIONS, args);
            parseCommandLine(line);
        } catch (ParseException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        } catch (IllegalCommandArgumentsException e) {
            throw e;
        }
        validateOptions();
        
        try {
            // Check that worker exists. An existing worker has a name.
            final int workerId = getWorkerId(worker);
            final WorkerConfig config = getWorkerSession().getCurrentWorkerConfig(workerId);
            if (config.getProperty(PropertiesConstants.NAME) == null) {
                throw new IllegalCommandArgumentsException("Error: No worker with the given Id could be found");
            }

            switch (operation) {
                case LIST: {
                    printAuthorizedClientsGen2(getWorkerSession().getAuthorizedClientsGen2(workerId));
                    break;
                }
                case ADD: {
                    CertificateMatchingRule rule = new CertificateMatchingRule(matchSubjectWithType, MatchIssuerWithType.ISSUER_DN_BCSTYLE, matchSubjectWithValue, matchIssuerWithValue, description);
                    getWorkerSession().addAuthorizedClientGen2(workerId, rule);
                    printAuthorizedClientsGen2(Arrays.asList(rule));
                    break;
                }
                case REMOVE: {
                    CertificateMatchingRule rule = new CertificateMatchingRule(matchSubjectWithType, MatchIssuerWithType.ISSUER_DN_BCSTYLE, matchSubjectWithValue, matchIssuerWithValue, description);
                    getWorkerSession().removeAuthorizedClientGen2(workerId, rule);
                    printAuthorizedClientsGen2(Arrays.asList(rule));
                    break;
                }
            }

            this.getOutputStream().println("\n\n");
            return 0;

        } catch (IllegalArgumentException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        } catch (RemoteException e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
    
    /**
     * Prints the list of authorized clients to the output stream.
     * @param authClients Clients to print
     */
    protected void printAuthorizedClientsGen2(final Collection<CertificateMatchingRule> authClients) {
        for (final CertificateMatchingRule client : authClients) {
            this.getOutputStream().println("  " + client.getMatchSubjectWithType() + ": " + client.getMatchSubjectWithValue() + ", " + client.getMatchIssuerWithType() + ": " + client.getMatchIssuerWithValue() + " Description: " + client.getDescription() + "\n");
        }
    }
}
