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
import static org.signserver.testutils.CLITestHelper.assertNotPrinted;
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
        int code = cli.execute("authorizedclients", "-worker", "_NonExistingWorkerName_", "-add", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule");
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
        int code = cli.execute("authorizedclients", "-worker", "_NonExistingWorkerName_", "-remove", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule");
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
        int code = cli.execute("authorizedclients", "-worker", "_NonExistingWorkerName_", "-list");
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
        int code = cli.execute("authorizedclients", "-worker", "112244", "-add", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule");
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
        int code = cli.execute("authorizedclients", "-worker", "112244", "-remove", "-matchSubjectWithType", "SUBJECT_RDN_CN", "-matchSubjectWithValue", "Client One", "-matchIssuerWithValue", "CN=AdminCA1, C=SE", "-description", "my rule");
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
        int code = cli.execute("authorizedclients", "-worker", "112244", "-list");
        assertEquals("return code", -1, code);
        assertPrinted("error message", cli.getOut(), "Error: No worker with the given Id could be found");
    }
    
    /**
     * Tests adding, listing, adding one more entry, listing again, removing 
     * entry and then listing again.
     * @throws Exception 
     */
    @Test
    public void testAddListAndRemove() throws Exception {
        LOG.info("testAddListAndRemove");
        try {
            test.addCMSSigner1();
            
            // Add
            assertEquals("execute add", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-add", 
                    "-matchSubjectWithType", "SUBJECT_RDN_CN",
                    "-matchSubjectWithValue", "Client Two",
                    "-matchIssuerWithValue", "CN=ManagementCA1, C=SE",
                    "-description", "My description"));
            assertPrinted("prints new rule with SUBJECT_RDN_CN", cli.getOut(), "SUBJECT_RDN_CN");
            assertPrinted("prints new rule with Client Two", cli.getOut(), "Client Two");
            assertPrinted("prints new rule with CN=ManagementCA1, C=SE", cli.getOut(), "CN=ManagementCA1, C=SE");
            
            // List
            assertEquals("execute list", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrinted("prints rule with SUBJECT_RDN_CN", cli.getOut(), "SUBJECT_RDN_CN");
            assertPrinted("prints rule with Client Two", cli.getOut(), "Client Two");
            assertPrinted("prints rule with CN=ManagementCA1, C=SE", cli.getOut(), "CN=ManagementCA1, C=SE");
            assertPrinted("prints rule with My description", cli.getOut(), "My description");
            
            // Add one more + also explicitly specify matchIssuerWithType
            assertEquals("execute add 2", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-add", 
                    "-matchSubjectWithType", "CERTIFICATE_SERIALNO",
                    "-matchSubjectWithValue", "123456",
                    "-matchIssuerWithType", "ISSUER_DN_BCSTYLE",
                    "-matchIssuerWithValue", "CN=ManagementCA2, OU=Testing, C=SE",
                    "-description", "Other description"));
            assertPrinted("prints new rule with CERTIFICATE_SERIALNO", cli.getOut(), "CERTIFICATE_SERIALNO");
            assertPrinted("prints new rule with 123456", cli.getOut(), "123456");
            assertPrinted("prints new rule with CN=ManagementCA2, OU=Testing, C=SE", cli.getOut(), "CN=ManagementCA2, OU=Testing, C=SE");
            assertPrinted("prints new rule with Other description", cli.getOut(), "Other description");
            
            // List both entries
            assertEquals("execute list 2", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrinted("prints rule 1 with SUBJECT_RDN_CN", cli.getOut(), "SUBJECT_RDN_CN");
            assertPrinted("prints rule 1 with Client Two", cli.getOut(), "Client Two");
            assertPrinted("prints rule 1 with CN=ManagementCA1, C=SE", cli.getOut(), "CN=ManagementCA1, C=SE");
            assertPrinted("prints rule 1 with My description", cli.getOut(), "My description");
            
            assertPrinted("prints rule 2 with CERTIFICATE_SERIALNO", cli.getOut(), "CERTIFICATE_SERIALNO");
            assertPrinted("prints rule 2 with 123456", cli.getOut(), "123456");
            assertPrinted("prints rule 2 with CN=ManagementCA2, OU=Testing, C=SE", cli.getOut(), "CN=ManagementCA2, OU=Testing, C=SE");
            assertPrinted("prints rule 2 with Other description", cli.getOut(), "Other description");
            
            // Remove first entry
            assertEquals("execute remove", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-remove", 
                    "-matchSubjectWithType", "SUBJECT_RDN_CN",
                    "-matchSubjectWithValue", "Client Two",
                    "-matchIssuerWithValue", "CN=ManagementCA1, C=SE",
                    "-description", "My description")); // TODO: Currently the description field has to be provided. Should it be like that?
            assertPrinted("prints new rule with SUBJECT_RDN_CN", cli.getOut(), "SUBJECT_RDN_CN");
            assertPrinted("prints new rule with Client Two", cli.getOut(), "Client Two");
            assertPrinted("prints new rule with CN=ManagementCA1, C=SE", cli.getOut(), "CN=ManagementCA1, C=SE");
            
            // List second entry only now
            assertEquals("execute list 2", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertNotPrinted("prints rule 1 with SUBJECT_RDN_CN", cli.getOut(), "SUBJECT_RDN_CN");
            assertNotPrinted("prints rule 1 with Client Two", cli.getOut(), "Client Two");
            assertNotPrinted("prints rule 1 with CN=ManagementCA1, C=SE", cli.getOut(), "CN=ManagementCA1, C=SE");
            assertNotPrinted("prints rule 1 with My description", cli.getOut(), "My description");
            
            assertPrinted("prints rule 2 with CERTIFICATE_SERIALNO", cli.getOut(), "CERTIFICATE_SERIALNO");
            assertPrinted("prints rule 2 with 123456", cli.getOut(), "123456");
            assertPrinted("prints rule 2 with CN=ManagementCA2, OU=Testing, C=SE", cli.getOut(), "CN=ManagementCA2, OU=Testing, C=SE");
            assertPrinted("prints rule 2 with Other description", cli.getOut(), "Other description");
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }

    /**
     * Tests the format for the output.
     * @throws Exception 
     */
    @Test
    public void testListFormat() throws Exception {
        LOG.info("testListFormat");
        try {
            test.addCMSSigner1();
            
            // Add
            assertEquals("execute add", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-add", 
                    "-matchSubjectWithType", "SUBJECT_RDN_CN",
                    "-matchSubjectWithValue", "Client Two",
                    "-matchIssuerWithValue", "CN=ManagementCA1, C=SE",
                    "-description", "My description"));
            assertPrinted("prints new rule", cli.getOut(), "  SUBJECT_RDN_CN: Client Two | ISSUER_DN_BCSTYLE: CN=ManagementCA1, C=SE | Description: My description");
            
            // List
            assertEquals("execute list", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrinted("prints rule 1", cli.getOut(), "  SUBJECT_RDN_CN: Client Two | ISSUER_DN_BCSTYLE: CN=ManagementCA1, C=SE | Description: My description");
            
            // Add one more
            assertEquals("execute add 2", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-add", 
                    "-matchSubjectWithType", "CERTIFICATE_SERIALNO",
                    "-matchSubjectWithValue", "123456",
                    "-matchIssuerWithValue", "CN=ManagementCA2, OU=Testing, C=SE",
                    "-description", "Other description"));
            assertPrinted("prints new rule with CERTIFICATE_SERIALNO", cli.getOut(), "  CERTIFICATE_SERIALNO: 123456 | ISSUER_DN_BCSTYLE: CN=ManagementCA2, OU=Testing, C=SE | Description: Other description");
            
            // List both entries
            assertEquals("execute list 2", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrinted("prints rule 1", cli.getOut(), "  SUBJECT_RDN_CN: Client Two | ISSUER_DN_BCSTYLE: CN=ManagementCA1, C=SE | Description: My description");
            assertPrinted("prints rule 2", cli.getOut(), "  CERTIFICATE_SERIALNO: 123456 | ISSUER_DN_BCSTYLE: CN=ManagementCA2, OU=Testing, C=SE | Description: Other description");
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }
}
