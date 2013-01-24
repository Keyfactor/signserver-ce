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

import java.util.List;
import java.util.Set;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.dbprotection.DatabaseProtectionError;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.signserver.admin.cli.defaultimpl.AdminCommandHelper;
import org.signserver.admin.cli.defaultimpl.archive.*;
import org.signserver.cli.spi.AbstractCommand;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;

/**
 * 
 *
 * @version $Id$
 */
public class QueryAuditLogCommand extends AbstractCommand {

    private AdminCommandHelper helper = new AdminCommandHelper();
    private ArchiveCLIUtils utils = new ArchiveCLIUtils();
    
    public static final String QUERY = "query";
    public static final String FROM = "from";
    public static final String TO = "to";
    
    /** The command line options */
    private static final Options OPTIONS;
    
    private int from = 0;
    private int to = 0;
    
    @Override
    public String getDescription() {
        return "Query the content of the audit log";
    }

    static {
        OPTIONS = new Options();
        OPTIONS.addOption(QUERY, false, "Query the audit log");
        OPTIONS.addOption(FROM, true, "Lower index in search result (0-based)");
        OPTIONS.addOption(TO, true, "Upper index in search result (0-based)");
    }
    
    // TODO: Need to figure out a CLI syntax allowing an unbounded number of criterias to be specified, compare to how searching is done in the EJBCA GUI
    @Override
    public String getUsages() {
        return "Usage: signserver auditlog -query <TODO>\n"
                    + "Example: signserver -query TODO\n\n";
    }
    
    @Override
    public int execute(String[] args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
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
            
            // TODO: Parse arguments and build QueryCriteria
            final QueryCriteria qc1 = QueryCriteria.create().add(Criteria.orderDesc(AuditRecordData.FIELD_TIMESTAMP));
            
            // TODO: Parse arguments and get row numbers to query
            
            // Perform the query
            List<? extends AuditLogEntry> entries = helper.getWorkerSession().selectAuditLogs(from, to, qc1, device);
            for (AuditLogEntry entry : entries) {
                
                // Render the result
                final StringBuilder buff = new StringBuilder();
                buff.append(entry.getTimeStamp()).append(", ")
                        .append(entry.getEventTypeValue()).append(", ")
                        .append(entry.getEventStatusValue()).append(", ")
                        .append(entry.getAuthToken()).append(", ")
                        .append(entry.getModuleTypeValue()).append(", ")
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
            System.err.println("Exception: " + e.getClass() + ", caused by: " + e.getCause().getClass());
            
            // Is it a verification failure?
            if (e.getCause() instanceof DatabaseProtectionError) {
                DatabaseProtectionError error = (DatabaseProtectionError) e.getCause();
                // TODO: (or not): Doesn't seems like we can do more than printing this error message
//                if (error.getEntity() != null) {
//                    System.err.println("Entity: " + error.getEntity() + ", data: " + error.getEntity().getRowProtection());
//                }
                System.err.println(error.getMessage());
//                e.printStackTrace();
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
        
        err.println("parseCommandLine");
        
        // TODO: we might want to enfore the range options to avoid possible memory exhaustion
        final String fromString = line.getOptionValue(FROM);
        final String toString = line.getOptionValue(TO);
        
        if (fromString != null) {
            try {
                from = Integer.parseInt(fromString);
            } catch (NumberFormatException ex) {
                throw new ParseException("Invalid from index value: " + fromString);
            }
        }
        
        if (toString != null) {
            try {
                to = Integer.parseInt(toString);
            } catch (NumberFormatException ex) {
                throw new ParseException("Invalid to index value: " + toString);
            }
        }
    }
    
}
