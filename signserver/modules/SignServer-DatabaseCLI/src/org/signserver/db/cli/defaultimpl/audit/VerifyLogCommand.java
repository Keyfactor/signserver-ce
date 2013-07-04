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
package org.signserver.db.cli.defaultimpl.audit;

import java.util.HashMap;
import java.util.Map;
import javax.persistence.EntityManager;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.ejbca.database.audit.IntegrityProtectedAuditReader;
import org.signserver.cli.spi.CommandFailureException;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.db.cli.defaultimpl.AbstractDatabaseCommand;

/**
 * Command for verifying the auditlog.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class VerifyLogCommand extends AbstractDatabaseCommand {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(VerifyLogCommand.class);
   
    private static final String ALL = "all";
    private static final String NODE = "node";
    
    private static final Options OPTIONS;
    
    static {
        OPTIONS = new Options();
        OPTIONS.addOption(ALL, false, "Verify all nodes and start from sequence number 0");
        OPTIONS.addOption(NODE, true, "Verify only the specified node(s) and optionally from the specified offset");
    }
    
    @Override
    public String getDescription() {
        return "Perform database integrity protection validation of the audit log";
    }

    @Override
    public String getUsages() {
        return "Usage: verifylog -all\n"
             + "       verifylog [-node NODENAME[:OFFSET] ...]\n"
                + "\nVerifies logs from all nodes starting at sequence number 0 or only from the specified nodes and optional sequence number offsets specified."
                + "\nIf the nodename is suffixed with a colon and an number then the verification for that node is started from that sequence number."
                + "\nThe JDBC connector of the database might have to be put on the classpath. See the example below.\n"
                + "\nExample: a) signserver-db audit verifylog -all"
                + "\nExample: b) signserver-db audit verifylog -node server1 -node server2:708"
                + "\nExample: c) OPTIONAL_CLASSPATH=/usr/share/java/mysql-connector-java.jar signserver-db audit verifylog -all";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("URL of config: " + VerifyLogCommand.class.getResource("/conf/databaseprotection.properties"));
        }
        
        try {
            final CommandLine commandLine = new GnuParser().parse(OPTIONS, args);
            if (!commandLine.hasOption(ALL) && !commandLine.hasOption(NODE)) {
                throw new IllegalCommandArgumentsException("Missing -all or -nodes argument(s)");
            }
            if (commandLine.hasOption(ALL) && commandLine.hasOption(NODE)) {
                throw new IllegalCommandArgumentsException("Can not specify -all while there is an -node specified");
            }
            
            final Map<String, Long> sequences;
            if (commandLine.hasOption(ALL)) {
                sequences = null;
            } else {
                sequences = new HashMap<String, Long>();
                final String[] nodes = commandLine.getOptionValues(NODE);
                for (final String node : nodes) {
                    final String name;
                    final long offset;
                    if (node.contains(":")) {
                        name = node.substring(0, node.indexOf(":"));
                        offset = Long.parseLong(node.substring(node.indexOf(":") + 1));
                    } else {
                        name = node;
                        offset = 0L;
                    }
                    sequences.put(name, offset);
                }
            }
            return validateAuditLog(getEntityManager(), sequences);
        } catch (ParseException ex) {
            throw new IllegalCommandArgumentsException(ex.getMessage());
        }
    }

    public int validateAuditLog(final EntityManager entityManager, Map<String, Long> sequences) {
        final long startTime = System.currentTimeMillis();
        long rowCount = 0;
        
        final IntegrityProtectedAuditReader ipar = new IntegrityProtectedAuditReader(entityManager, 0, System.currentTimeMillis(), 10000, sequences);
        
        LOG.info("The following nodes exists: " + ipar.getNodeIds());
        LOG.info("Start sequences: " + ipar.getStartSequences());
        
        sequences = new HashMap<String, Long>();
        
        while ( true ) {
        	final int chunkLength = ipar.getNextVerifiedChunk();
        	if ( ipar.isDone() ) {
        		break;
        	}
        	rowCount += chunkLength;
        	if (rowCount>0) {
        		LOG.info("Progress: node=" + ipar.getNodeId() + " rowCount=" + rowCount);
                        LOG.info("Last sequence number: " + ipar.getLastSeqNrFromPreviousChunk());
                        sequences.put(ipar.getNodeId(), ipar.getLastSeqNrFromPreviousChunk());
                        
        	} else {
        		LOG.info("Progress: no valid entries found so far!");
        	}
        }
        final AuditLogValidationReport auditLogValidationReport = ipar.getAuditLogValidationReport();
        final int errors = auditLogValidationReport.errors().size();
        final int warnings = auditLogValidationReport.warnings().size();
        LOG.info("Audit log validation completed in " + (System.currentTimeMillis()-startTime)/1000 + " seconds. " + rowCount
                + " rows found. Errors: " + errors + " Warnings: " + warnings);
        
        final int result;
        if (errors > 0) {
            LOG.error("Verification finished with error(s)");
            result = -1;
        } else if (warnings > 0) {
            LOG.error("Verification finished with warning(s)");
            result = -2;
        } else {
            LOG.info("Verification finished with success");
            LOG.info("Last sequences: " + sequences);
            result = 0;
        }
        return result;
    }
    
}
