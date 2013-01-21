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
    
    @Override
    public String getDescription() {
        return "TODO";
    }

    // TODO: Need to figure out a CLI syntax allowing an unbounded number of criterias to be specified, compare to how searching is done in the EJBCA GUI
    @Override
    public String getUsages() {
        return "Usage: signserver auditlog query <TODO>\n"
                    + "Example: signserver query TODO\n\n";
    }
    
    @Override
    public int execute(String[] args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        if (args.length != 1) {
            throw new IllegalCommandArgumentsException("Wrong number of arguments");
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
            List<? extends AuditLogEntry> entries = helper.getWorkerSession().selectAuditLogs(0, 10, qc1, device);
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
    
}
