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

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.regex.Pattern;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.util.CertTools;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;
import org.signserver.common.SignServerUtil;
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
    public static final String MATCH_ISSUER_WITH_TYPE = "matchIssuerWithType";
    public static final String MATCH_ISSUER_WITH_VALUE = "matchIssuerWithValue";
    public static final String DESCRIPTION = "description";
    public static final String CERT = "cert";

    /** The command line options. */
    private static final Options OPTIONS;
    
    private static final Pattern SERIAL_PATTERN = Pattern.compile("\\bSERIALNUMBER=", Pattern.CASE_INSENSITIVE);

    static {
        OPTIONS = new Options();
        OPTIONS.addOption(ADD, false, "Add a new client authorization rule");
        OPTIONS.addOption(REMOVE, false, "Remove a client authorization rule");
        OPTIONS.addOption(LIST, false, "List all client authorization rules");

        OPTIONS.addOption(WORKER, true, "Worker name or ID");
        OPTIONS.addOption(MATCH_SUBJECT_WITH_TYPE, true, "Match subject with type. One of " + Arrays.toString(MatchSubjectWithType.values()) + ".");
        OPTIONS.addOption(MATCH_SUBJECT_WITH_VALUE, true, "Match subject with value");
        OPTIONS.addOption(MATCH_ISSUER_WITH_TYPE, true, "Match issuer with type. One of " + Arrays.toString(MatchIssuerWithType.values()) + ".");
        OPTIONS.addOption(MATCH_ISSUER_WITH_VALUE, true, "Match issuer with value");
        OPTIONS.addOption(DESCRIPTION, true, "An optional description text");
        OPTIONS.addOption(CERT, true, "Certificate providing match values");
    }

    private String operation;
    private String worker;
    private MatchSubjectWithType matchSubjectWithType;
    private String matchSubjectWithValue;
    private MatchIssuerWithType matchIssuerWithType = MatchIssuerWithType.ISSUER_DN_BCSTYLE;
    private String matchIssuerWithValue;
    private String description;
    private String cert;

    @Override
    public String getDescription() {
        return "Add/list/remove client authorization rules.";
    }

    @Override
    public String getUsages() {
        return "Usage: signserver authorizedclients -worker <worker name or ID> -list \n"
             + "       signserver authorizedclients -worker <worker name or ID> <-add/-remove> -matchSubjectWithType <SUBJECT_MATCH_TYPE> -matchSubjectWithValue <value> [-matchIssuerWithType <ISSUER_MATCH_TYPE>] -matchIssuerWithValue <issuer DN> [-description <textual description>]\n"
             + "       signserver authorizedclients -worker <worker name or ID> <-add/-remove> -matchSubjectWithType <SUBJECT_MATCH_TYPE> [-matchIssuerWithType <ISSUER_MATCH_TYPE>] [-description <textual description>] -cert <PEM file>\n"
             + "Example 1: authorizedclients -worker CMSSigner -list\n"
             + "Example 2: authorizedclients -worker CMSSigner -add -matchSubjectWithType SUBJECT_RDN_CN -matchSubjectWithValue \"Client One\" -matchIssuerWithValue \"CN=AdminCA1, C=SE\"\n"
             + "Example 3: authorizedclients -worker CMSSigner -add -matchSubjectWithType SUBJECT_RDN_CN -matchSubjectWithValue \"Client One\" -matchIssuerWithType ISSUER_DN_BCSTYLE -matchIssuerWithValue \"CN=AdminCA1, C=SE\" -description \"my rule\"\n"
             + "Example 4: authorizedclients -worker CMSSigner -add -matchSubjectWithType CERTIFICATE_SERIALNO -matchIssuerWithType ISSUER_DN_BCSTYLE -cert /tmp/admin.pem\n"
             + "Example 5: authorizedclients -worker CMSSigner -remove -matchSubjectWithType CERTIFICATE_SERIALNO -matchIssuerWithType ISSUER_DN_BCSTYLE -cert /tmp/admin.pem";
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

        final String matchIssuerWithTypeString = line.getOptionValue(MATCH_ISSUER_WITH_TYPE, null);
        if (matchIssuerWithTypeString != null) {
            try {
                matchIssuerWithType = MatchIssuerWithType.valueOf(matchIssuerWithTypeString);
            } catch (IllegalArgumentException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unknown matchIssuerWithType: " + ex.getMessage());
                }
                throw new IllegalCommandArgumentsException("Unknown " + MATCH_ISSUER_WITH_TYPE + " value provided. Possible values are: " + Arrays.toString(MatchIssuerWithType.values()));
            }
        }

        matchSubjectWithValue = line.getOptionValue(MATCH_SUBJECT_WITH_VALUE, null);
        matchIssuerWithValue = line.getOptionValue(MATCH_ISSUER_WITH_VALUE, null);
        if (matchIssuerWithValue != null) {
            try {
                matchIssuerWithValue = CertTools.stringToBCDNString(matchIssuerWithValue);
            } catch (IllegalArgumentException | StringIndexOutOfBoundsException ex) {
                throw new IllegalCommandArgumentsException("Invalid " + MATCH_ISSUER_WITH_VALUE + " value provided: " + matchIssuerWithValue);
            }
        }
        description = line.getOptionValue(DESCRIPTION, null);
        cert = line.getOptionValue(CERT, null);
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
                if (cert != null &&
                    (matchSubjectWithValue != null || matchIssuerWithValue != null)) {
                    throw new IllegalCommandArgumentsException("Can not specify -cert at the same time as -matchSubjectWithValue and/or -matchIssuerWithValue");
                }
                if (cert == null) {
                    if (matchSubjectWithValue == null || matchIssuerWithValue == null) {
                        throw new IllegalCommandArgumentsException("Must specify -matchSubjectWithValue and -matchIssuerWithValue when not specifying -cert");
                    }
                }
            }
        }
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        final CommandLine line;
        try {
            // Parse the command line
            line = new DefaultParser().parse(OPTIONS, args);
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
                    this.getOutputStream().println(
                    "OBSERVE that this command displays the current configuration which\n"
                    + "doesn't have to be the same as the active configuration.\n"
                    + "Configurations are activated with the reload command. \n\n"
                    + "The current list of authorized clients to worker " + workerId + " are :\n");

                    printAuthorizedClientsGen2(getWorkerSession().getAuthorizedClientsGen2(workerId));
                    break;
                }
                case ADD: {
                    final CertificateMatchingRule rule = getRuleFromParams();
                    getWorkerSession().addAuthorizedClientGen2(workerId, rule);
                    this.getOutputStream().println();
                    printAuthorizedClientsGen2(Arrays.asList(rule));
                    break;
                }
                case REMOVE: {
                    final CertificateMatchingRule rule = getRuleFromParams();
                    this.getOutputStream().println();
                    printAuthorizedClientsGen2(Arrays.asList(rule));
                    if (getWorkerSession().removeAuthorizedClientGen2(workerId, rule)) {
                        this.getOutputStream().println("Rule removed");
                    } else {
                        throw new CommandFailureException("Rule did not exist or could not be removed");
                    }
                    break;
                }
            }

            this.getOutputStream().println();
            return 0;

        } catch (IllegalArgumentException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        } catch (RemoteException e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
    
    private CertificateMatchingRule getRuleFromParams()
            throws CommandFailureException, IllegalArgumentException {
        final X509Certificate x509Cert =
                cert != null ? SignServerUtil.getCertFromFile(cert) : null;
        
        String subjectValue = x509Cert == null ? matchSubjectWithValue :
                                                 getSubjectValueFromCert(x509Cert);
        final String issuerValue = x509Cert == null ? matchIssuerWithValue :
                                                      getIssuerValueFromCert(x509Cert);

        if (matchSubjectWithType == MatchSubjectWithType.CERTIFICATE_SERIALNO) {
            // normalize serial number
            try {
                final BigInteger sn =
                        new BigInteger(subjectValue, 16);
                subjectValue = sn.toString(16);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Illegal serial number: " + matchSubjectWithValue);
            }
        }
        CertificateMatchingRule rule =
                new CertificateMatchingRule(matchSubjectWithType,
                                            matchIssuerWithType,
                                            subjectValue,
                                            issuerValue,
                                            description);

        return rule;
    }
    
    private String getSubjectValueFromCert(final X509Certificate x509Cert) throws CommandFailureException {
        String certstring = CertTools.getSubjectDN(x509Cert);
        certstring = SERIAL_PATTERN.matcher(certstring).replaceAll("SN=");
        final String altNameString = CertTools.getSubjectAlternativeName(x509Cert);
        final DNFieldExtractor dnExtractor = new DNFieldExtractor(certstring, DNFieldExtractor.TYPE_SUBJECTDN);
        final DNFieldExtractor anExtractor = new DNFieldExtractor(altNameString, DNFieldExtractor.TYPE_SUBJECTALTNAME);
        int parameter = DNFieldExtractor.CN;
        DNFieldExtractor usedExtractor = dnExtractor;

        if (matchSubjectWithType == MatchSubjectWithType.CERTIFICATE_SERIALNO) {
            final BigInteger sn = x509Cert.getSerialNumber();
            return sn.toString(16);
        } else {
            switch (matchSubjectWithType) {
                case SUBJECT_RDN_CN:
                    parameter = DNFieldExtractor.CN;
                    break;
                case SUBJECT_RDN_SERIALNO:
                    parameter = DNFieldExtractor.SN;
                    break;
                case SUBJECT_RDN_DC:
                    parameter = DNFieldExtractor.DC;
                    break;
                case SUBJECT_RDN_ST:
                    parameter = DNFieldExtractor.ST;
                    break;
                case SUBJECT_RDN_L:
                    parameter = DNFieldExtractor.L;
                    break;
                case SUBJECT_RDN_O:
                    parameter = DNFieldExtractor.O;
                    break;
                case SUBJECT_RDN_OU:
                    parameter = DNFieldExtractor.OU;
                    break;
                case SUBJECT_RDN_TITLE:
                    parameter = DNFieldExtractor.T;
                    break;
                case SUBJECT_RDN_UID:
                    parameter = DNFieldExtractor.UID;
                    break;
                case SUBJECT_RDN_E:
                    parameter = DNFieldExtractor.E;
                    break;
                case SUBJECT_ALTNAME_RFC822NAME:
                    parameter = DNFieldExtractor.RFC822NAME;
                    usedExtractor = anExtractor;
                    break;
                case SUBJECT_ALTNAME_MSUPN:
                    parameter = DNFieldExtractor.UPN;
                    usedExtractor = anExtractor;
                    break;
                default: // It should not happen though
                    throw new AssertionError(matchSubjectWithType.name());
            }
            
            final int size = usedExtractor.getNumberOfFields(parameter);
            final String matchSubjectName = matchSubjectWithType.name();
        
            if (size == 0) {
                throw new CommandFailureException("DN field " + matchSubjectName +
                                              " not found in subject DN of certificate");
            } else if (size > 1) {
                this.getOutputStream().println("More than one component matching " + matchSubjectName +
                         ", picking the first one");
            }

            return usedExtractor.getField(parameter, 0);
        }
    }

    private String getIssuerValueFromCert(final X509Certificate x509Cert) {
        // Only one MatchIssuerType is supported now
        return CertTools.stringToBCDNString(x509Cert.getIssuerX500Principal().getName());
    }
    
    /**
     * Prints the list of authorized clients to the output stream.
     * @param authClients Clients to print
     */
    protected void printAuthorizedClientsGen2(final Collection<CertificateMatchingRule> authClients) {
        if (authClients.isEmpty()) {
            this.getOutputStream().println("  No authorized clients exists.\n");
        } else {
            authClients.forEach((client) -> {
                this.getOutputStream().println("  "
                        + client.getMatchSubjectWithType() + ": " + client.getMatchSubjectWithValue() + " | "
                        + client.getMatchIssuerWithType() + ": " + client.getMatchIssuerWithValue()
                        + (StringUtils.isBlank(client.getDescription()) ? "" : " | Description: " + client.getDescription()));
            });
        }
    }
}
