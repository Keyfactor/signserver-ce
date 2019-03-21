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
package org.signserver.cli;

import org.apache.log4j.Logger;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.signserver.testutils.CLITestHelper;
import static org.signserver.testutils.CLITestHelper.assertPrinted;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for the ClientsAuthorizationCommand.
 *
 * For unit tests see he ClientsAuthorizationCommandUnitTest class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ClientsAuthorizationCommandTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ClientsAuthorizationCommandTest.class);

    private final ModulesTestCase test = new ModulesTestCase();
    private final CLITestHelper cli = test.getAdminCLI();
    
    /** 
     * Tests that providing a non-existing worker name to the add operation gives an error message.
     * @throws Exception 
     */
    @Test
    public void testAddWithUnknownWorkerName() throws Exception {
        LOG.info("testAddWithUnknownWorkerName");
        int code = cli.execute("clients", "-worker", "_NonExistingWorkerName_", "-add", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule");
        assertEquals("return code", -1, code);
        assertPrinted("error message", cli.getOut(), "No worker with the given name could be found");
    }

    /** 
     * Tests that providing a non-existing worker name to the remove operation gives an error message.
     * @throws Exception 
     */
    @Test
    public void testRemoveWithUnknownWorkerName() throws Exception {
        LOG.info("testRemoveWithUnknownWorkerName");
        int code = cli.execute("clients", "-worker", "_NonExistingWorkerName_", "-remove", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule");
        assertEquals("return code", -1, code);
        assertPrinted("error message", cli.getOut(), "No worker with the given name could be found");
    }
    
    /** 
     * Tests that providing a non-existing worker name to the list operation gives an error message.
     * @throws Exception 
     */
    @Test
    public void testListWithUnknownWorkerName() throws Exception {
        LOG.info("testListWithUnknownWorkerName");
        int code = cli.execute("clients", "-worker", "_NonExistingWorkerName_", "-list");
        assertEquals("return code", -1, code);
        assertPrinted("error message", cli.getOut(), "No worker with the given name could be found");
    }

    /** 
     * Tests that providing a non-existing worker Id to the add operation gives an error message.
     * Note: this tests assumes there is no worker with Id 112244.
     * @throws Exception 
     */
    @Test
    public void testAddWithUnknownWorkerId() throws Exception {
        LOG.info("testAddWithUnknownWorkerId");
        int code = cli.execute("clients", "-worker", "112244", "-add", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule");
        assertEquals("return code", -1, code);
        assertPrinted("error message", cli.getOut(), "Error: No worker with the given Id could be found");
    }

    /** 
     * Tests that providing a non-existing worker Id to the remove operation gives an error message.
     * Note: this tests assumes there is no worker with Id 112244.
     * @throws Exception 
     */
    @Test
    public void testRemoveWithUnknownWorkerId() throws Exception {
        LOG.info("testAddWithUnknownWorkerId");
        int code = cli.execute("clients", "-worker", "112244", "-remove", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule");
        assertEquals("return code", -1, code);
        assertPrinted("error message", cli.getOut(), "Error: No worker with the given Id could be found");
    }
    
    /** 
     * Tests that providing a non-existing worker Id to the list operation gives an error message.
     * Note: this tests assumes there is no worker with Id 112244.
     * @throws Exception 
     */
    @Test
    public void testListWithUnknownWorkerId() throws Exception {
        LOG.info("testAddWithUnknownWorkerId");
        int code = cli.execute("clients", "-worker", "112244", "-list");
        assertEquals("return code", -1, code);
        assertPrinted("error message", cli.getOut(), "Error: No worker with the given Id could be found");
    }
}
