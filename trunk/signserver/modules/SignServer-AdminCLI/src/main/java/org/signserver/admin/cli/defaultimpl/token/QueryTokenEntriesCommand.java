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
package org.signserver.admin.cli.defaultimpl.token;

import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang.time.FastDateFormat;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.util.query.Elem;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.signserver.admin.common.query.QueryUtil;
import org.signserver.admin.cli.defaultimpl.AbstractAdminCommand;
import org.signserver.admin.cli.defaultimpl.AdminCommandHelper;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.server.cryptotokens.TokenEntry;
import org.signserver.server.cryptotokens.TokenSearchResults;
import static org.signserver.common.SignServerConstants.TOKEN_ENTRY_FIELDS_ALIAS;

/**
 * Command for printing key aliases in a crypto token and optionally other
 * information including the certificate chain.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class QueryTokenEntriesCommand extends AbstractAdminCommand {

    private final AdminCommandHelper helper = new AdminCommandHelper();
    
    /** Option strings */
    public static final String TOKEN = "token";
    public static final String FROM = "from";
    public static final String LIMIT = "limit";
    public static final String CRITERIA = "criteria";
    public static final String VERBOSE = "v";
 
    /** The command line options */
    private static final Options OPTIONS;
    private static final Set<String> longFields;
    private static final Set<String> dateFields;
    private static final Set<RelationalOperator> noArgOps;
    private static final Set<String> allowedFields;
    
    private static final String INDENT = "   ";

    private String tokenIdOrName;
    private int from = 0;
    private int limit = 0;
    private boolean verbose = false;
    private List<Elem> terms;

    private final FastDateFormat fdf = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZ");
    
    @Override
    public String getDescription() {
        return "Query the content of a token";
    }

    static {
        OPTIONS = new Options();
        OPTIONS.addOption(TOKEN, true, "Worker ID or name of CryptoToken");
        OPTIONS.addOption(CRITERIA, true, "Search criteria (can specify multiple criterias)");
        OPTIONS.addOption(FROM, true, "Lower index in search result (0-based)");
        OPTIONS.addOption(LIMIT, true, "Maximum number of search results");
        OPTIONS.addOption(VERBOSE, false, "Output the certificate chain and other information available in each entry");
        
        longFields = new HashSet<>();
        longFields.add(AuditRecordData.FIELD_SEQUENCENUMBER);
        
        dateFields = new HashSet<>();
        dateFields.add(AuditRecordData.FIELD_TIMESTAMP);
        
        noArgOps = new HashSet<>();
        noArgOps.add(RelationalOperator.NULL);
        noArgOps.add(RelationalOperator.NOTNULL);
        
        // allowed fields
        allowedFields = new HashSet<>();
        allowedFields.add(TOKEN_ENTRY_FIELDS_ALIAS); // TODO: Defined in CryptoTokenHelper.TokenEntryFields
    }
    
    @Override
    public String getUsages() {
        return "Usage: signserver querytokenentries -token <id or name> -limit <number> -operator <operator> [-criteria  \"<field> <op> <value>\" [-criteria...]] [-from <index>] [-v]\n"
                + "<field> is a field name from the token: alias\n"
                + "<op> is a relational operator: EQ, NEQ or LIKE\n"
                + "Example: signserver querytokenentries -token CryptoTokenHSM -from 0 -limit 10\n"
                + "Example: signserver querytokenentries -token CryptoTokenHSM -criteria \"alias EQ key123\n"
                + "Example: signserver querytokenentries -token CryptoTokenHSM -from 0 -limit 10 -criteria \"alias NEQ key1\" -criteria \"alias NEQ key4\"\n"
                + "Example: signserver querytokenentries -token CryptoTokenHSM -criteria \"alias LIKE key%\n\n";
    }
    
    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        
        try {
            // Parse the command line
            parseCommandLine(new GnuParser().parse(OPTIONS, args));
        } catch (ParseException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        }
        
        try {
            final WorkerIdentifier wi = WorkerIdentifier.createFromIdOrName(tokenIdOrName);

            final QueryCriteria qc = QueryCriteria.create();
            
            if (terms != null && !terms.isEmpty()) {
                qc.add(QueryUtil.andAll(terms, 0));
            }

            // Perform the query
            TokenSearchResults searchResults;
            
            int startIndex = from;
            final int max = limit < 1 ? 10 : limit;
            do {
                searchResults = helper.getWorkerSession().searchTokenEntries(wi, startIndex, max, qc, verbose, Collections.<String, Object>emptyMap());
            
                int i = startIndex;
                for (TokenEntry entry : searchResults.getEntries()) {
                    renderEntry(i, entry, verbose);
                    i++;
                }
                startIndex = startIndex + searchResults.getEntries().size();
            } while (limit < 1 && searchResults.isMoreEntriesAvailable());
            
            if (searchResults.getNumMoreEntries() != null) {
                getOutputStream().println("... " + searchResults.getNumMoreEntries() + " more entries exists.");
            } else if (searchResults.isMoreEntriesAvailable() != null) {
                if (searchResults.isMoreEntriesAvailable()) {
                    getOutputStream().println("... more entries exists.");
                } else {
                    getOutputStream().println("... no more entries.");
                }
            } else {
                getOutputStream().println("... no information about more entries.");
            }
                        
            out.println("\n\n");
            return 0;

        } catch (Exception e) {            
            // Is it a verification failure?
            if (e.getCause() instanceof DatabaseProtectionException) {
                DatabaseProtectionException error = (DatabaseProtectionException) e.getCause();
                err.println(error.getMessage());
                // TODO: (or not): Doesn't seems like we can do more than printing this error message
                if (error.getEntity() != null) {
                    System.err.println("Entity: " + error.getEntity() + ", data: " + error.getEntity().getRowProtection());
                }

                return -1;
            } else {
                throw new UnexpectedCommandFailureException(e);
            }
        }
    }

    private void parseCommandLine(CommandLine line) throws ParseException {
        if (!line.hasOption(TOKEN)) {
            throw new ParseException("Missing required option: " + TOKEN);
        }
        tokenIdOrName = line.getOptionValue(TOKEN);
        
        final String fromString = line.getOptionValue(FROM);
        final String limitString = line.getOptionValue(LIMIT);
        
        verbose = line.hasOption(VERBOSE);
        
        if (fromString != null) {
            try {
                from = Integer.parseInt(fromString);
            } catch (NumberFormatException ex) {
                throw new ParseException("Invalid from index value: " + fromString);
            }
        }
        
        if (limitString != null) {
            try {
                limit = Integer.parseInt(limitString);
                
                if (limit <= 0) {
                    throw new ParseException("Too small value specified for limit: " + limit);
                }
            } catch (NumberFormatException ex) {
                throw new ParseException("Invalid limit value: " + limitString);
            }
        } else {
            limit = -1;
        }
        
        final String[] criterias = line.getOptionValues(CRITERIA);
        
        terms = new LinkedList<>();
        if (criterias != null && criterias.length > 0) {
            for (final String criteria : criterias) {
                try {
                    final Term term = parseCriteria(criteria);
                    terms.add(term);
                } catch (NumberFormatException e) {
                    throw new ParseException("Invalid critera, expected a numeric value: " + criteria);
                } catch (IllegalArgumentException e) {
                    throw new ParseException("Invalid critera specified: " + e.getMessage() + ": " + 
                            criteria);
                } catch (java.text.ParseException e) {
                    throw new ParseException("Invalid date specified: " + criteria);
                }
            }
        }
        
        
    }
    
    static Term parseCriteria(final String criteria)
            throws IllegalArgumentException, NumberFormatException, java.text.ParseException {
        return QueryUtil.parseCriteria(criteria, allowedFields, noArgOps,
                Collections.<String>emptySet(), longFields, dateFields);
    }
    
    private void renderEntry(int i, TokenEntry entry, boolean verbose) {
        getOutputStream().println(i + ": " + entry.getAlias());
        if (verbose) {
            final StringBuilder sb = new StringBuilder();
            sb.append(INDENT).append("Type: ").append(entry.getType()).append("\n");
            if (entry.getCreationDate() != null) {
                sb.append(INDENT).append("Creation date: ").append(entry.getCreationDate()).append("\n");
            }
            try {
                if (entry.getParsedChain() != null) {
                    sb.append(INDENT).append("Certificate chain: ").append("\n").append(Arrays.toString(entry.getParsedChain())).append("\n");
                }
            } catch (CertificateException ex) {
                sb.append(INDENT).append("Certificate chain: ").append("Unable to parse: ").append(ex.getMessage()).append("\n");
            }
            try {
                if (entry.getParsedTrustedCertificate() != null) {
                    sb.append(INDENT).append("Trusted certificate: ").append("\n").append(entry.getParsedTrustedCertificate()).append("\n");
                }
            } catch (CertificateException ex) {
                sb.append(INDENT).append("Trusted certificate: ").append("Unable to parse: ").append(ex.getMessage()).append("\n");
            }
            if (entry.getInfo() != null && !entry.getInfo().isEmpty()) {
                sb.append(INDENT).append("Additional information:\n");
                for (Map.Entry<String, String> info : entry.getInfo().entrySet()) {
                    sb.append(INDENT).append(INDENT).append(info.getKey()).append(": ").append(info.getValue()).append("\n");
                }
            }
            sb.append("\n");
            getOutputStream().println(sb.toString());
        }
    }
    
}
