/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.admin.cli.defaultimpl;

import java.util.Collection;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.MatchSubjectWithType;

/**
 *
 * @author user
 */
public class ClientsAuthorizationCommand extends AbstractCommand {

    public static final String ADD = "add";
    public static final String REMOVE = "remove";
    public static final String LIST = "list";
    public static final String MATCH_SUBJECT_WITH_TYPE = "matchSubjectWithType";
    public static final String MATCH_SUBJECT_WITH_VALUE = "matchSubjectWithValue";
    public static final String DESCRIPTION = "description";
    
    /** The command line options. */
    private static final Options OPTIONS;
    
    static {
        OPTIONS = new Options();
        OPTIONS.addOption(ADD, false, "Add a new client authorization rule");
        OPTIONS.addOption(REMOVE, false, "Remove a client authorization rule");
        OPTIONS.addOption(LIST, false, "List all client authorization rules");

        OPTIONS.addOption(MATCH_SUBJECT_WITH_TYPE, true, "Match subject with type");
        OPTIONS.addOption(MATCH_SUBJECT_WITH_VALUE, true, "Match subject with value");
        OPTIONS.addOption(DESCRIPTION, true, "A textual representation");
    }
    
    private String operation;
    private MatchSubjectWithType matchSubjectWithType;
    private String matchSubjectWithValue;
    private String description;
    
    @Override
    public String getDescription() {
        return "Authorizes clients";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver clients <-add/-remove/list> -worker <worker name or ID> -matchSubjectWithType <MATCH_TYPE> -matchSubjectWithValue <value> -matchIssuerWithValue <issuer DN> [-description <textual description>]\n"
                    + "Example 1: clients -add -worker CMSSigner -matchSubjectWithType RDN_CN -matchSubjectWithValue \"Client One\" -matchIssuerWithValue \"CN=AdminCA1, C=SE\" -description \"my rule\"\n\n";
    }
    
    /**
     * Reads all the options from the command line.
     *
     * @param line The command line to read from
     */
    private void parseCommandLine(final CommandLine line)
        throws IllegalCommandArgumentsException {
        
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
        
        description = line.getOptionValue(DESCRIPTION, null);
    }

    /**
     * Checks that all mandatory options are given.
     */
    private void validateOptions() throws IllegalCommandArgumentsException {
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

        switch (operation) {
            case LIST: {
                this.getOutputStream().println("TODO: List"); // TODO
                break;
            }
            case ADD: {
                this.getOutputStream().println("TODO: Add"); // TODO
                break;
            }
            case REMOVE: {
                this.getOutputStream().println("TODO: Remove"); // TODO
                break;
            }
        }

        try {
            // TODO getWorkerSession().addAuthorizedClientGen2(signerid, authClient);
            // TODO printAuthorizedClients(getWorkerSession().getAuthorizedClientsGen2(signerid));

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
    protected void printAuthorizedClients(final Collection<AuthorizedClient> authClients) {
        for (final AuthorizedClient client : authClients) {
            this.getOutputStream().println("  " + client.getCertSN() + ", " + client.getIssuerDN() + "\n");
        }
    }
}
