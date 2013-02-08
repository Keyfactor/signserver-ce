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

import javax.persistence.EntityManager;
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
    
    @Override
    public String getDescription() {
        return "Perform database integrity protection validation of the audit log";
    }

    @Override
    public String getUsages() {
        return "Usage: verifylog\n"
                + "\nThe JDBC connector of the database might have to be put on the classpath. See the example below.\n"
                + "Example: a) OPTIONAL_CLASSPATH=/usr/share/java/mysql-connector-java.jar signserver-db audit verifylog";
    }

    @Override
    public int execute(String... args) throws IllegalCommandArgumentsException, CommandFailureException, UnexpectedCommandFailureException {
        
        if (args.length > 0) {
            throw new IllegalCommandArgumentsException("Unexpected argument specified");
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("URL of config: " + VerifyLogCommand.class.getResource("/conf/databaseprotection.properties"));
        }
        
        return validateAuditLog(getEntityManager());
    }

    public int validateAuditLog(final EntityManager entityManager) {
        final long startTime = System.currentTimeMillis();
        long rowCount = 0;
        final IntegrityProtectedAuditReader ipar = new IntegrityProtectedAuditReader(entityManager, 0, System.currentTimeMillis(), 10000);
        while ( true ) {
        	final int chunkLength = ipar.getNextVerifiedChunk();
        	if ( ipar.isDone() ) {
        		break;
        	}
        	rowCount += chunkLength;
        	if (rowCount>0) {
        		LOG.info("Progress: node=" + ipar.getNodeId() + " rowCount=" + rowCount);
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
            result = 0;
        }
        return result;
    }
    
}
