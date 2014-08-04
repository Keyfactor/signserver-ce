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
package org.signserver.admin.cli.defaultimpl.archive;

import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.signserver.admin.cli.AdminCLIUtils;
import org.signserver.admin.cli.defaultimpl.AdminCommandHelper;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.ArchiveDataVO;
import org.signserver.common.ArchiveMetadata;
import org.signserver.server.archive.Archivable;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.Elem;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;

/**
 * Query contents of the archive.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class QueryArchiveCommand extends AbstractCommand {

    private AdminCommandHelper helper = new AdminCommandHelper();
    
    /** Option strings */
    public static final String FROM = "from";
    public static final String LIMIT = "limit";
    public static final String CRITERIA = "criteria";
    public static final String HEADER = "header";
    
    /** The command line options */
    private static final Options OPTIONS;
    private static final Set<String> intFields;
    private static final Set<String> dateFields;
    private static final Set<RelationalOperator> noArgOps;
    private static final Set<String> allowedFields;
    
    private int from;
    private int limit;
    private boolean printHeader;
    private QueryCriteria qc;
 
    private static final String HEADER_FIELDS = "archiveid, time, type, signerid, requestIssuerDN, requestCertSerialNumber, requestIP";
    private static final String HEADER_NAMES =  "Archive ID, Time, Type, Signer ID, Issuer DN, Certificate Serial Number, IP Address";

    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");

    static {
        OPTIONS = new Options();
        OPTIONS.addOption(CRITERIA, true, "Search criteria (can specify multiple criterias)");
        OPTIONS.addOption(FROM, true, "Lower index in search result (0-based)");
        OPTIONS.addOption(LIMIT, true, "Maximum number of search results");
        OPTIONS.addOption(HEADER, false, "Print a column header");
    
        intFields = new HashSet<String>();
        intFields.add(ArchiveMetadata.SIGNER_ID);
        
        dateFields = new HashSet<String>();
        dateFields.add(ArchiveMetadata.TIME);
        
        noArgOps = new HashSet<RelationalOperator>();
        noArgOps.add(RelationalOperator.NULL);
        noArgOps.add(RelationalOperator.NOTNULL);
     
        allowedFields = new HashSet<String>();
        allowedFields.add(ArchiveMetadata.ARCHIVE_ID);
        allowedFields.add(ArchiveMetadata.REQUEST_CERT_SERIAL_NUMBER);
        allowedFields.add(ArchiveMetadata.REQUEST_IP);
        allowedFields.add(ArchiveMetadata.REQUEST_ISSUER_DN);
        allowedFields.add(ArchiveMetadata.SIGNER_ID);
        allowedFields.add(ArchiveMetadata.TIME);
        allowedFields.add(ArchiveMetadata.TYPE);
    }
        
    @Override
    public String getDescription() {
        return "Query the content of the archive";
    }

    @Override
    public String getUsages() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException,
            CommandFailureException, UnexpectedCommandFailureException {
        qc = QueryCriteria.create().add(Criteria.orderDesc(ArchiveMetadata.TIME));
        
        try {
            parseCommandLine(new GnuParser().parse(OPTIONS, args));
        } catch (ParseException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        }
        
        try {
            if (printHeader) {
                out.println(HEADER_NAMES);
                out.println(HEADER_FIELDS);
            }
    
            // Perform the query
            Collection<? extends ArchiveMetadata> entries = helper.getWorkerSession().searchArchive(from, limit, qc);
    
            for (final ArchiveMetadata entry : entries) {
                // render the result
                final StringBuilder buff = new StringBuilder();
                final String type =
                        entry.getType() == ArchiveDataVO.TYPE_REQUEST ?
                              Archivable.TYPE_REQUEST : Archivable.TYPE_RESPONSE;
                final String issuer =
                        entry.getRequestIssuerDN() != null ? entry.getRequestIssuerDN() : "";
                final String serial =
                        entry.getRequestCertSerialNumber() != null ?
                                entry.getRequestCertSerialNumber() : "";
                final String ip =
                        entry.getRequestIP() != null ? entry.getRequestIP() : "Local EJB";
                
                buff.append(entry.getArchiveId()).append(", ")
                    .append(sdf.format(entry.getTime())).append(", ")
                    .append(type).append(", ")
                    .append(entry.getSignerId()).append(", ")
                    .append(issuer).append(", ")
                    .append(serial).append(", ")
                    .append(ip);
            
                out.println(buff.toString());
            }
            
            out.println("\n\n");
            return 0;
        } catch (Exception e) {
            throw new UnexpectedCommandFailureException(e);
        }
    }
    
    private void parseCommandLine(final CommandLine line) throws ParseException {
        final String fromString = line.getOptionValue(FROM);
        final String limitString = line.getOptionValue(LIMIT);
        
        printHeader = line.hasOption(HEADER);
        
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
            throw new ParseException("Must specify a limit.");
        }
        
        final String[] criterias = line.getOptionValues(CRITERIA);
        
        final List<Elem> terms = new LinkedList<Elem>();
        
        if (criterias != null && criterias.length > 0) {
            for (final String criteria : criterias) {
                try {
                    final Term term =
                            AdminCLIUtils.parseCriteria(criteria, allowedFields, 
                                    noArgOps, intFields, Collections.<String>emptySet(), dateFields);
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
        
            Elem all = AdminCLIUtils.andAll(terms, 0);
            qc.add(all);
        } 
    }
}
