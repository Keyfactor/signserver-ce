/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.admin.cli.defaultimpl;

import java.util.Arrays;
import java.util.Collection;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;

/**
 *
 * @author user
 */
public class ClientsAuthorizationCommand extends AbstractAdminCommand {

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

        if (line.hasOption(ADD)) {
            operation = ADD;
        } else if (line.hasOption(REMOVE)) {
            operation = REMOVE;
        } else if (line.hasOption(LIST)) {
            operation = LIST;
        }
        
        final String matchSubjectWithTypeString = line.getOptionValue(MATCH_SUBJECT_WITH_TYPE, null);
        if (matchSubjectWithTypeString != null) {
            // TODO try catch
            matchSubjectWithType = MatchSubjectWithType.valueOf(matchSubjectWithTypeString);
        }
        
        final String matchSubjectWithValueString = line.getOptionValue(MATCH_SUBJECT_WITH_VALUE, null);
        if (matchSubjectWithValueString != null) {
            // TODO
            matchSubjectWithValue = matchSubjectWithValueString;
        }
        
        final String matchIssuerWithValueString = line.getOptionValue(MATCH_ISSUER_WITH_VALUE, null);
        if (matchIssuerWithValueString != null) {
            // TODO
            matchIssuerWithValue = matchIssuerWithValueString;
        }
        
        description = line.getOptionValue(DESCRIPTION, null);
    }

    /**
     * Checks that all mandatory options are given.
     */
    private void validateOptions() throws IllegalCommandArgumentsException {
        if (worker == null) {
            throw new IllegalCommandArgumentsException("Missing -worker");
        }
        
        if (operation == null) {
            throw new IllegalCommandArgumentsException("Missing operation: -add, -remove or -list");
        } else switch (operation) {
            case ADD:
            case REMOVE: {
                if (matchSubjectWithType == null) {
                    throw new IllegalCommandArgumentsException("Missing -matchSubjectWithType");
                }
                if (matchSubjectWithValue == null) {
                    throw new IllegalCommandArgumentsException("Missing -matchSubjectWithValue");
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
            
            switch (operation) {
                case LIST: {
                    printAuthorizedClientsGen2(getWorkerSession().getAuthorizedClientsGen2(getWorkerId(worker)));
                    break;
                }
                case ADD: {
                    CertificateMatchingRule rule = new CertificateMatchingRule(matchSubjectWithType, MatchIssuerWithType.ISSUER_DN_BCSTYLE, matchSubjectWithValue, matchIssuerWithValue, description);
                    getWorkerSession().addAuthorizedClientGen2(getWorkerId(worker), rule);
                    printAuthorizedClientsGen2(Arrays.asList(rule));
                    break;
                }
                case REMOVE: {
                    CertificateMatchingRule rule = new CertificateMatchingRule(matchSubjectWithType, MatchIssuerWithType.ISSUER_DN_BCSTYLE, matchSubjectWithValue, matchIssuerWithValue, description);
                    getWorkerSession().removeAuthorizedClientGen2(getWorkerId(worker), rule);
                    printAuthorizedClientsGen2(Arrays.asList(rule));
                    break;
                }
            }

            this.getOutputStream().println("\n\n");
            return 0;

        } catch (IllegalArgumentException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());  
        } catch (Exception e) {
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
