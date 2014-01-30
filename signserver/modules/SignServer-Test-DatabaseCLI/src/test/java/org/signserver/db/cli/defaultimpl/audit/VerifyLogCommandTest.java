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

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceException;
import junit.framework.TestCase;
import static junit.framework.TestCase.assertEquals;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.dbprotection.ProtectedDataConfiguration;
import org.signserver.cli.spi.IllegalCommandArgumentsException;
import org.signserver.db.cli.Main;
import org.signserver.db.cli.defaultimpl.DatabaseHelper;

/**
 * More extensive tests for the database CLI which also modifies the audit log.
 * It uses some other nodeIds "server1" and "server2".
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class VerifyLogCommandTest extends TestCase {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(VerifyLogCommandTest.class);
    
    private static final String JDBC_ERROR = "This test requires the JDBC drivers to be present on the classpath. Put the database connector as lib/ext/jdbc/jdbc.jar. Configure signserver_cli.properties.";
    
    private final VerifyLogCommand command = new VerifyLogCommand();
    
    private EntityManager entityManager;
    private final String SERVER1 = "server1";
    private final String SERVER2 = "server2";
    
    public VerifyLogCommandTest(String testName) {
        super(testName);
    }
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        ConfigurationHolder.addConfigurationResource("/databaseprotection.properties");
    }
    
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }
    
    private String getRequiredProperty(final String property) throws IllegalCommandArgumentsException {
        final String result = getConfiguration().getProperty(property);
        if (result == null || result.trim().isEmpty()) {
            throw new IllegalCommandArgumentsException("Missing required configuration property: " + property);
        }
        return result.trim();
    }
    
    protected Properties getConfiguration() {
        return getCLIProperties();
    }
    
    private static Properties getCLIProperties() {
        Properties properties = new Properties();
        InputStream in = null; 
        try {
            in = Main.class.getResourceAsStream("/signserver_cli.properties");
            if (in != null) {
                properties.load(in);
            }
        } catch (IOException ex) {
            LOG.error("Could not load configuration: " + ex.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOG.error("Failed to close configuration", ex);
                }
            }
        }
        return properties;
    }
    
    public EntityManager getEntityManager() throws IllegalCommandArgumentsException {
        if (entityManager == null) {
            final DatabaseHelper helper = new DatabaseHelper();
            final String type = getRequiredProperty("dbcli.database.name");
            if (type == null) {
                throw new IllegalCommandArgumentsException("Unknown value for dbcli.database.name. Possible values are" + helper.getTypes());
            }
            
            entityManager = helper.getEntityManager(type, getConfiguration().getProperty("dbcli.database.driver"), getRequiredProperty("dbcli.database.url"), getRequiredProperty("dbcli.database.username"), getConfiguration().getProperty("dbcli.database.password", ""));
        }
        return entityManager;
    }
     
    /**
     * Creates the following log.
     * <pre>
     * select nodeId,sequenceNumber,searchDetail1 from AuditRecordData order by nodeId, sequenceNumber;
        +---------+----------------+------------------+
        | nodeId  | sequenceNumber | searchDetail1    |
        +---------+----------------+------------------+
        | server1 |              0 | Log on server1 0 |
        | server1 |              1 | Log on server1 1 |
        | server1 |              2 | Log on server1 2 |
        | server1 |              3 | Log on server1 3 |
        | server1 |              4 | Log on server1 4 |
        | server1 |              5 | Log on server1 5 |
        | server1 |              6 | Log on server1 6 |
        | server1 |              7 | Log on server1 7 |
        | server2 |              0 | Log on server2 0 |
        | server2 |              1 | Log on server2 1 |
        | server2 |              2 | Log on server2 2 |
        | server2 |              3 | Log on server2 3 |
        | server2 |              4 | Log on server2 4 |
        | server2 |              5 | Log on server2 5 |
        | server2 |              6 | Log on server2 6 |
        | server2 |              7 | Log on server2 7 |
        +---------+----------------+------------------+
        16 rows in set (0.00 sec)
     * </pre>
     */
    private void fillLogOk() throws Exception {
        LOG.info("Filling log ok");
        long server1Sequence = 0;
        long server2Sequence = 0;
        
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
    }
    
    private void fillLogServer1MissingSequence() throws Exception {
        LOG.info("Filling log server with error");
        long server1Sequence = 0;
        long server2Sequence = 0;
        
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        
        // The following row has been deleted (sequenceNumber=4):
        server1Sequence++;
        //log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
    }
    
        /**
     * Creates the following log.
     * <pre>
     * select nodeId,sequenceNumber,searchDetail1 from AuditRecordData order by nodeId, sequenceNumber;
        +---------+----------------+---------------------+
        | nodeId  | sequenceNumber | searchDetail1       |
        +---------+----------------+---------------------+
        | server1 |              7 | Log on server1 - 7  |
        | server1 |              8 | Log on server1 - 8  |
        | server1 |              9 | Log on server1 - 9  |
        | server1 |             10 | Log on server1 - 10 |
        | server1 |             11 | Log on server1 - 11 |
        | server1 |             12 | Log on server1 - 12 |
        | server1 |             13 | Log on server1 - 13 |
        | server1 |             14 | Log on server1 - 14 |
        | server2 |              5 | Log on server2 - 5  |
        | server2 |              6 | Log on server2 - 6  |
        | server2 |              7 | Log on server2 - 7  |
        | server2 |              8 | Log on server2 - 8  |
        | server2 |              9 | Log on server2 - 9  |
        | server2 |             10 | Log on server2 - 10 |
        | server2 |             11 | Log on server2 - 11 |
        | server2 |             12 | Log on server2 - 12 |
        +---------+----------------+---------------------+
        16 rows in set (0.00 sec)
     * </pre>
     */
    private void fillLogArchived() throws Exception {
        LOG.info("Filling log archived");
        long server1Sequence = 7;
        long server2Sequence = 5;
        
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
        log(SERVER1, server1Sequence, "Log on " + SERVER1 + " - " + server1Sequence++);
        log(SERVER2, server2Sequence, "Log on " + SERVER2 + " - " + server2Sequence++);
    }
    
    private void clearLog() throws Exception {
        LOG.info("Clearing log");
        final EntityManager em = getEntityManager();
        em.getTransaction().begin();
        final int deletedCount = em.createQuery("DELETE FROM AuditRecordData a where a.nodeId=? or a.nodeId=?").setParameter(1, SERVER1).setParameter(2, SERVER2).executeUpdate();
        em.getTransaction().commit();
        LOG.info("Delete count: " + deletedCount);
    }
    
    private void log(final String nodeId, final Long sequenceNumber, final String searchDetail1) {
        log(new Date(), LogEventType.RELOAD_WORKER_CONFIG, EventStatus.SUCCESS, LogModuleType.SERVICE, LogServiceType.SIGNSERVER, "CLI User", null, searchDetail1, null, null, nodeId, sequenceNumber);
    }
     
    private void log(final Date time, final EventType eventType, final EventStatus eventStatus, final ModuleType module,
            final ServiceType service, final String authToken, final String customId, final String searchDetail1, final String searchDetail2,
            final Map<String, Object> additionalDetails, final String nodeId, final Long sequenceNumber) throws AuditRecordStorageException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(String.format(">log:%s:%s:%s:%s:%s:%s", eventType, eventStatus, module, service, authToken, additionalDetails));
        }
        try {
            final EntityManager em = getEntityManager();
            em.getTransaction().begin();
            final Long timeStamp = time.getTime();
            final AuditRecordData auditRecordData = new AuditRecordData(nodeId, sequenceNumber, timeStamp, eventType, eventStatus, authToken,
                    service, module, customId, searchDetail1, searchDetail2, additionalDetails);
            em.persist(auditRecordData);
            em.getTransaction().commit();
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            throw new AuditRecordStorageException(e.getMessage(), e);
        } finally {
            if (LOG.isTraceEnabled()) {
                LOG.trace("<log");
            }
        }
    }
   
    private enum LogEventType implements EventType {
        RELOAD_WORKER_CONFIG;

        @Override
        public boolean equals(EventType t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    } 
    private enum LogModuleType implements ModuleType {
        SERVICE;

        @Override
        public boolean equals(ModuleType t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }
    private enum LogServiceType implements ServiceType {
        SIGNSERVER;

        @Override
        public boolean equals(ServiceType t) {
            throw new UnsupportedOperationException("Not supported yet.");
        }
    }
    
    // TODO add test methods here. The name must begin with 'test'. For example:
    // public void testHello() {}
    
    public void testProtectionConfigured() throws Exception {
        LOG.info("testProtectionConfigured");
        LOG.info("Config file: " + Main.class.getResource("/databaseprotection.properties"));
        if (!ProtectedDataConfiguration.useDatabaseIntegrityProtection("AuditRecordData")) {
            throw new Exception("Test environment not configured to sign audit log");
        }
    }
    
    public void testEmptyDatabase() throws Exception {
        LOG.info("testEmptyDatabase");
        
        clearLog();
        
        try {
            HashMap<String, Long> sequences = new HashMap<String, Long>();
            sequences.put(SERVER1, 0L);
            sequences.put(SERVER2, 0L);
            final int actual = command.validateAuditLog(getEntityManager(), sequences);
            assertEquals("return code", Main.RETURN_SUCCESS, actual);
        } catch (PersistenceException ex) {
            throw new Exception(JDBC_ERROR, ex);
        }
    }
    
    /**
     * Tests that the audit verifylog command completes successful.
     */
     public void testVerifyLog() throws Exception {
        LOG.info("testVerifyLog");
        
        clearLog();
        fillLogOk();
        
        try {
            final int actual = command.validateAuditLog(getEntityManager(), null);
            assertEquals("return code", Main.RETURN_SUCCESS, actual);
        } catch (PersistenceException ex) {
            throw new Exception(JDBC_ERROR, ex);
        }
    }
     
    /**
     * Tests that the audit verifylog command completes successful when all nodes
     * are explicitly specified.
     */
     public void testVerifyLogAllNodesSpecified() throws Exception {
        LOG.info("testVerifyLogAllNodesSpecified");
        
        clearLog();
        fillLogOk();
        
        try {
            HashMap<String, Long> sequences = new HashMap<String, Long>();
            sequences.put(SERVER1, 0L);
            sequences.put(SERVER2, 0L);
            final int actual = command.validateAuditLog(getEntityManager(), sequences);
            assertEquals("return code", Main.RETURN_SUCCESS, actual);
        } catch (PersistenceException ex) {
            throw new Exception(JDBC_ERROR, ex);
        }
    }

    /**
     * Tests verify log when one sequence number is missing.
     */
     public void testVerifyLogMissingSequence() throws Exception {
        LOG.info("testVerifyLogMissingSequence");
        
        // Setup a log with two nodes, server1=ok, server2=missing entries
        // then verification should fail as one sequence number is missing
        clearLog();
        
        try {
            fillLogServer1MissingSequence();
            final int actual = command.validateAuditLog(getEntityManager(), null);
            assertEquals("return code", -1, actual);
        } catch (PersistenceException ex) {
            throw new Exception(JDBC_ERROR, ex);
        } finally {
            // We need to clean up the log otherwise other test cases might fail
            clearLog();
        }
    }
     
    /**
     * Tests verify log where the first sequences are missing/archived
     */
     public void testVerifyLogMissingArchivedSequences() throws Exception {
        LOG.info("testVerifyLogMissingArchivedSequences");
        
        // Setup a log with two nodes, the first entries are missing/archived
        // then verification should fail as verification can not start from 0
        clearLog();
        
        try {
            fillLogArchived();
            final int actual = command.validateAuditLog(getEntityManager(), null);
            assertEquals("return code", -1, actual);
        } catch (PersistenceException ex) {
            throw new Exception(JDBC_ERROR, ex);
        } finally {
            // We need to clean up the log otherwise other test cases might fail
            clearLog();
        }
    }
     
    /**
     * Tests verify log for only the specified node.
     */
     public void testVerifyLogOneNodeSpecified() throws Exception {
        LOG.info("testVerifyLogOneNodeSpecified");
        
        // Setup a log with two nodes, server1=ok, server2=missing entries
        // then verification should succeed anyway as we only look at server1
        clearLog();
        
        try {
            fillLogServer1MissingSequence();
            HashMap<String, Long> sequences = new HashMap<String, Long>();
            sequences.put(SERVER2, 0L);
            final int actual = command.validateAuditLog(getEntityManager(), sequences);
            assertEquals("return code", Main.RETURN_SUCCESS, actual);
        } catch (PersistenceException ex) {
            throw new Exception(JDBC_ERROR, ex);
        } finally {
            // We need to clean up the log otherwise other test cases might fail
            clearLog();
        }
    }
     
    /**
     * Tests that the audit verifylog command completes successful when all nodes
     * are explicitly specified and the start values are specified as the first
     * entries has been archived.
     */
     public void testVerifyLogArchivedAllNodesSpecified() throws Exception {
        LOG.info("testVerifyLogArchivedAllNodesSpecified");
        
        clearLog();
        
        try {
            fillLogArchived();
            HashMap<String, Long> sequences = new HashMap<String, Long>();
            sequences.put(SERVER1, 7L);
            sequences.put(SERVER2, 5L);
            final int actual = command.validateAuditLog(getEntityManager(), sequences);
            assertEquals("return code", Main.RETURN_SUCCESS, actual);
        } catch (PersistenceException ex) {
            throw new Exception(JDBC_ERROR, ex);
        } finally {
            // We need to clean up the log otherwise other test cases might fail
            clearLog();
        }
    }
}

