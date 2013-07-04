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
package org.signserver.db.cli;

import javax.persistence.PersistenceException;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.signserver.testutils.CLITestHelper;

/**
 * Tests for the database CLI.
 *
 * Tests in this class does not alter the database.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class DatabaseCLITest extends TestCase {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DatabaseCLITest.class);
    
    private static final String JDBC_ERROR = "This test requires the JDBC drivers to be present on the classpath. Put the database connector as lib/ext/jdbc/jdbc.jar. Configure signserver_cli.properties.";
    
    private CLITestHelper cli = getDatabaseCLI();
    
    public DatabaseCLITest(String testName) {
        super(testName);
    }
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }
    
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }
    
    public CLITestHelper getDatabaseCLI() {
        if (cli == null) {
            cli = new CLITestHelper(Main.class);
        }
        return cli;
    }
    
    /**
     * Tests that non-existing command gives an error return code.
     */
    @Test
    public void testNonExistingCommand() throws Exception {
        LOG.info("testNonExistingCommand");
        final int actual = cli.execute(new String[] {"_any_non_existing_command_123_"});
        assertEquals("return code", Main.RETURN_INVALID_ARGUMENTS, actual);
    }
    
    /**
     * Tests that non-existing command argument gives an error return code.
     */
    @Test
    public void testVerifyLogUnexpectedArgument() throws Exception {
        LOG.info("testVerifyLogUnexpectedArgument");
        final int actual = cli.execute(new String[] {"audit", "verifylog", "_invalid_argument_123_"});
        assertEquals("return code", Main.RETURN_INVALID_ARGUMENTS, actual);
    }
    
    /**
     * Tests that the audit verifylog command completes successful.
     */
    @Test
     public void testVerifyLog() throws Exception {
        LOG.info("testVerifyLog");
        LOG.info("Note: This could be long running. Clear the AuditRecordData table inbetween runs.\n"
                + "For HSQLDB this test can not be run while the application server is running.");
        try {
            final int actual = cli.execute(new String[] {"audit", "verifylog", "-all"});
            assertEquals("return code", Main.RETURN_SUCCESS, actual);
        } catch (PersistenceException ex) {
            throw new Exception(JDBC_ERROR, ex);
        }
    }
    
    // TODO add test methods here. The name must begin with 'test'. For example:
    // public void testHello() {}
}
