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
package org.signserver.admin.cli.defaultimpl.auditlog;

import java.sql.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.Elem;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.signserver.admin.cli.AdminCLIUtils;
import org.signserver.admin.cli.defaultimpl.AdminCommandHelper;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;

/**
 * 
 * AdminCLI command to query the audit log.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class QueryAuditLogCommand extends AbstractCommand {

    private AdminCommandHelper helper = new AdminCommandHelper();
    
    /** Option strings */
    public static final String QUERY = "query";
    public static final String FROM = "from";
    public static final String LIMIT = "limit";
    public static final String CRITERIA = "criteria";
    public static final String HEADER = "header";
 
    /** The command line options */
    private static final Options OPTIONS;
    private static final Set<String> longFields;
    private static final Set<String> dateFields;
    private static final Set<RelationalOperator> noArgOps;
    private static final Set<String> allowedFields;

    private int from = 0;
    private int limit = 0;
    private boolean printHeader = false;
    
    private static final String HEADER_FIELDS = "timeStamp, eventStatus, eventType, module, authToken, customId, searchDetail1, searchDetail2, nodeId, additionalDetails";
    private static final String HEADER_NAMES =  "Time, Outcome, Event, Module, Admin Subject, Admin Issuer, Admin Serial Number, Worker ID, Node, Details";
    
    private QueryCriteria qc;
    
    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");
    
    @Override
    public String getDescription() {
        return "Query the content of the audit log";
    }

    static {
        OPTIONS = new Options();
        OPTIONS.addOption(QUERY, false, "Query the audit log");
        OPTIONS.addOption(CRITERIA, true, "Search criteria (can specify multiple criterias)");
        OPTIONS.addOption(FROM, true, "Lower index in search result (0-based)");
        OPTIONS.addOption(LIMIT, true, "Maximum number of search results");
        OPTIONS.addOption(HEADER, false, "Print a column header");
        
        longFields = new HashSet<String>();
        longFields.add(AuditRecordData.FIELD_SEQUENCENUMBER);
        
        dateFields = new HashSet<String>();
        dateFields.add(AuditRecordData.FIELD_TIMESTAMP);
        
        noArgOps = new HashSet<RelationalOperator>();
        noArgOps.add(RelationalOperator.NULL);
        noArgOps.add(RelationalOperator.NOTNULL);
        
        // allowed fields from CESeCore
        // TODO: should maybe define this in CESeCore?
        allowedFields = new HashSet<String>();
        allowedFields.add(AuditRecordData.FIELD_ADDITIONAL_DETAILS);
        allowedFields.add(AuditRecordData.FIELD_AUTHENTICATION_TOKEN);
        allowedFields.add(AuditRecordData.FIELD_CUSTOM_ID);
        allowedFields.add(AuditRecordData.FIELD_EVENTSTATUS);
        allowedFields.add(AuditRecordData.FIELD_EVENTTYPE);
        allowedFields.add(AuditRecordData.FIELD_MODULE);
        allowedFields.add(AuditRecordData.FIELD_NODEID);
        allowedFields.add(AuditRecordData.FIELD_SEARCHABLE_DETAIL1);
        allowedFields.add(AuditRecordData.FIELD_SEARCHABLE_DETAIL2);
        allowedFields.add(AuditRecordData.FIELD_SERVICE);
        allowedFields.add(AuditRecordData.FIELD_SEQUENCENUMBER);
        allowedFields.add(AuditRecordData.FIELD_TIMESTAMP);
        
    }
    
    @Override
    public String getUsages() {
        return "Usage: signserver auditlog -query -limit <number> [-criteria  \"<field> <op> <value>\" [-criteria...]] [-from <index>] [-header]\n"
                + "<field> is a field name from the audit log: additionalDetails, authToken, customId, eventStatus, eventType, module, nodeId,\n"
                + "searchDetail1, searchDetail2, sequenceNumber, service, timeStamp\n"
                + "<op> is a relational operator: GT, GE, LT, LE, EQ, NEQ, LIKE, NULL, NOTNULL\n"
                + "Example: signserver auditlog -query -limit 10 -criteria \"customId EQ 1\n"
                + "Example: signserver auditlog -query -limit 10 -criteria \"timeStamp GT 1359623137000\" -criteria \"searchDetail2 EQ 1\"\n\n";
    }
    
    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        
        qc = QueryCriteria.create().add(Criteria.orderDesc(AuditRecordData.FIELD_TIMESTAMP));
        
        try {
            // Parse the command line
            parseCommandLine(new GnuParser().parse(OPTIONS, args));
        } catch (ParseException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        }
        
        try {
            
            // For now we only query on of the available audit devices
            Set<String> devices = helper.getAuditorSession().getQuerySupportingLogDevices();
            if (devices.isEmpty()) {
                throw new CommandFailureException("No log devices available for querying");
            }
            final String device = devices.iterator().next();
                       
            if (printHeader) {
                getOutputStream().println(HEADER_NAMES);
                getOutputStream().println(HEADER_FIELDS);
            }
            
            // Perform the query
            List<? extends AuditLogEntry> entries = helper.getWorkerSession().selectAuditLogs(from, limit, qc, device);
            for (AuditLogEntry entry : entries) {
                
                // Render the result
                final StringBuilder buff = new StringBuilder();
                buff.append(sdf.format(new Date(entry.getTimeStamp()))).append(", ")
                        .append(entry.getEventTypeValue()).append(", ")
                        .append(entry.getEventStatusValue()).append(", ")
                        .append(entry.getModuleTypeValue()).append(", ")
                        .append(entry.getAuthToken()).append(", ")
                        .append(entry.getCustomId()).append(", ")
                        .append(entry.getSearchDetail1()).append(", ")
                        .append(entry.getSearchDetail2()).append(", ")
                        .append(entry.getNodeId()).append(", ")
                        .append(entry.getMapAdditionalDetails());
                        
                getOutputStream().println(buff.toString());
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
        if (!line.hasOption(QUERY)) {
            // for now, we expect the -query option, might add additional command options further on
            throw new ParseException("Must specifiy the -query option");
        }
        
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
                            AdminCLIUtils.parseCriteria(criteria, allowedFields, noArgOps,
                                    Collections.<String>emptySet(), longFields, dateFields);
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
