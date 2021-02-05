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

import java.io.File;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.junit.Test;
import org.signserver.testutils.CLITestHelper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.signserver.testutils.CLITestHelper.assertNotPrinted;
import static org.signserver.testutils.CLITestHelper.assertPrinted;
import static org.signserver.testutils.CLITestHelper.assertPrintedLitterally;
import org.signserver.testutils.ModulesTestCase;

/**
 * System tests for the ClientsAuthorizationCommand.
 *
 * For unit tests see he ClientsAuthorizationCommandUnitTest class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ClientsAuthorizationCommandTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ClientsAuthorizationCommandTest.class);

    private final ModulesTestCase test = new ModulesTestCase();
    private final CLITestHelper cli = test.getAdminCLI();

    /**
     * Tests that providing a non-existing worker name to the add operation gives an error message.
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
                    "-matchIssuerWithValue", "CN=ManagementCA1,C=SE",
                    "-description", "My description"));
            assertPrinted("prints new rule with SUBJECT_RDN_CN", cli.getOut(), "SUBJECT_RDN_CN");
            assertPrinted("prints new rule with Client Two", cli.getOut(), "Client Two");
            assertPrinted("prints new rule with CN=ManagementCA1,C=SE", cli.getOut(), "CN=ManagementCA1,C=SE");

            // List
            assertEquals("execute list", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrinted("prints rule with SUBJECT_RDN_CN", cli.getOut(), "SUBJECT_RDN_CN");
            assertPrinted("prints rule with Client Two", cli.getOut(), "Client Two");
            assertPrinted("prints rule with CN=ManagementCA1,C=SE", cli.getOut(), "CN=ManagementCA1,C=SE");
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
            assertPrinted("prints new rule with CN=ManagementCA2, OU=Testing, C=SE", cli.getOut(), "CN=ManagementCA2,OU=Testing,C=SE");
            assertPrinted("prints new rule with Other description", cli.getOut(), "Other description");

            // List both entries
            assertEquals("execute list 2", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrinted("prints rule 1 with SUBJECT_RDN_CN", cli.getOut(), "SUBJECT_RDN_CN");
            assertPrinted("prints rule 1 with Client Two", cli.getOut(), "Client Two");
            assertPrinted("prints rule 1 with CN=ManagementCA1,C=SE", cli.getOut(), "CN=ManagementCA1,C=SE");
            assertPrinted("prints rule 1 with My description", cli.getOut(), "My description");

            assertPrinted("prints rule 2 with CERTIFICATE_SERIALNO", cli.getOut(), "CERTIFICATE_SERIALNO");
            assertPrinted("prints rule 2 with 123456", cli.getOut(), "123456");
            assertPrinted("prints rule 2 with CN=ManagementCA2, OU=Testing, C=SE", cli.getOut(), "CN=ManagementCA2,OU=Testing,C=SE");
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
            assertPrinted("prints new rule with CN=ManagementCA1,C=SE", cli.getOut(), "CN=ManagementCA1,C=SE");

            // List second entry only now
            assertEquals("execute list 2", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertNotPrinted("prints rule 1 with SUBJECT_RDN_CN", cli.getOut(), "SUBJECT_RDN_CN");
            assertNotPrinted("prints rule 1 with Client Two", cli.getOut(), "Client Two");
            assertNotPrinted("prints rule 1 with CN=ManagementCA1,C=SE", cli.getOut(), "CN=ManagementCA1,C=SE");
            assertNotPrinted("prints rule 1 with My description", cli.getOut(), "My description");

            assertPrinted("prints rule 2 with CERTIFICATE_SERIALNO", cli.getOut(), "CERTIFICATE_SERIALNO");
            assertPrinted("prints rule 2 with 123456", cli.getOut(), "123456");
            assertPrinted("prints rule 2 with CN=ManagementCA2, OU=Testing, C=SE", cli.getOut(), "CN=ManagementCA2,OU=Testing,C=SE");
            assertPrinted("prints rule 2 with Other description", cli.getOut(), "Other description");
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }

    /**
     * Tests the format for the output.
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
            assertPrinted("prints new rule", cli.getOut(), "  SUBJECT_RDN_CN: Client Two | ISSUER_DN_BCSTYLE: CN=ManagementCA1,C=SE | Description: My description");

            // List
            assertEquals("execute list", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrinted("prints rule 1", cli.getOut(), "  SUBJECT_RDN_CN: Client Two | ISSUER_DN_BCSTYLE: CN=ManagementCA1,C=SE | Description: My description");

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
            assertPrinted("prints rule 1", cli.getOut(), "  SUBJECT_RDN_CN: Client Two | ISSUER_DN_BCSTYLE: CN=ManagementCA1,C=SE | Description: My description");
            assertPrinted("prints rule 2", cli.getOut(), "  CERTIFICATE_SERIALNO: 123456 | ISSUER_DN_BCSTYLE: CN=ManagementCA2, OU=Testing, C=SE | Description: Other description");
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }


    /**
     * Tests upgrading of rules from the legacy rules by first adding some old
     * rules, then testing listing and removing.
     */
    @Test
    public void testUpgradeListAndRemove() throws Exception {
        LOG.info("testUpgradeListAndRemove");
        try {
            test.addCMSSigner1();

            // Add legacy rule 1
            assertEquals("execute legacy add 1", 0, cli.execute("addauthorizedclient", String.valueOf(test.getSignerIdCMSSigner1()),
                    "00123Ab", "CN=ManagementCA1, C=SE"));

            // Add legacy rule 2
            assertEquals("execute legacy add 2", 0, cli.execute("addauthorizedclient", String.valueOf(test.getSignerIdCMSSigner1()),
                    "789abcdef", "CN=foo2,O=Organization 2\\, inc.,C=SE"));

            // List
            assertEquals("execute list", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrinted("prints rule with CERTIFICATE_SERIALNO", cli.getOut(), "CERTIFICATE_SERIALNO");
            assertPrinted("prints rule with 789abcdef", cli.getOut(), "789abcdef");
            assertPrinted("prints rule with 123ab", cli.getOut(), "123ab");
            assertPrinted("prints rule with CN=ManagementCA1, C=SE", cli.getOut(), CertTools.stringToBCDNString("CN=ManagementCA1, C=SE"));
            assertTrue("prints rule with CN=foo2,O=Organization 2\\, inc.,C=SE", cli.getOut().toString().contains("CN=foo2,O=Organization 2\\, inc.,C=SE"));

            // Add one more but of new type
            assertEquals("execute new add 1", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-add",
                    "-matchSubjectWithType", "CERTIFICATE_SERIALNO",
                    "-matchSubjectWithValue", "123456",
                    "-matchIssuerWithType", "ISSUER_DN_BCSTYLE",
                    "-matchIssuerWithValue", "CN=ManagementCA2, OU=Testing, C=SE",
                    "-description", "Other description"));
            assertPrinted("prints new rule with CERTIFICATE_SERIALNO", cli.getOut(), "CERTIFICATE_SERIALNO");
            assertPrinted("prints new rule with 123456", cli.getOut(), "123456");
            assertPrinted("prints new rule with CN=ManagementCA2,OU=Testing,C=SE", cli.getOut(), "CN=ManagementCA2,OU=Testing,C=SE");
            assertPrinted("prints new rule with Other description", cli.getOut(), "Other description");

            // List all entries
            assertEquals("execute list 2", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrinted("prints rule with CERTIFICATE_SERIALNO", cli.getOut(), "CERTIFICATE_SERIALNO");
            assertPrinted("prints rule with 789abcdef", cli.getOut(), "789abcdef");
            assertPrinted("prints rule with 123ab", cli.getOut(), "123ab");
            assertPrinted("prints rule with CN=ManagementCA1,C=SE", cli.getOut(), "CN=ManagementCA1,C=SE");
            assertTrue("prints rule with CN=foo2,O=Organization 2\\, inc.,C=SE", cli.getOut().toString().contains("CN=foo2,O=Organization 2\\, inc.,C=SE"));

            assertPrinted("prints new rule 1 with CERTIFICATE_SERIALNO", cli.getOut(), "CERTIFICATE_SERIALNO");
            assertPrinted("prints new rule 1 with 123456", cli.getOut(), "123456");
            assertPrinted("prints new rule 1 with CN=ManagementCA2,OU=Testing,C=SE", cli.getOut(), "CN=ManagementCA2,OU=Testing,C=SE");
            assertPrinted("prints new rule 1 with Other description", cli.getOut(), "Other description");

            // Remove first legacy entry
            assertEquals("execute remove", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-remove",
                    "-matchSubjectWithType", "CERTIFICATE_SERIALNO",
                    "-matchSubjectWithValue", "123ab",
                    "-matchIssuerWithValue", "CN=ManagementCA1,C=SE",
                    "-description", "My description")); // TODO: Currently the description field has to be provided. Should it be like that?
            assertPrinted("prints removed rule with SUBJECT_RDN_CN", cli.getOut(), "CERTIFICATE_SERIALNO");
            assertPrinted("prints removed rule with Client Two", cli.getOut(), "123ab");
            assertPrinted("prints removed rule with CN=ManagementCA1,C=SE", cli.getOut(), "CN=ManagementCA1,C=SE");

            // List second entry only now
            assertEquals("execute list 3", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrinted("prints rule with CERTIFICATE_SERIALNO", cli.getOut(), "CERTIFICATE_SERIALNO");
            assertPrinted("prints rule with 789abcdef", cli.getOut(), "789abcdef");
            assertNotPrinted("prints rule with 123ab", cli.getOut(), "123ab");
            assertNotPrinted("prints rule with CN=ManagementCA1,C=SE", cli.getOut(), "CN=ManagementCA1,C=SE");
            assertTrue("prints rule with CN=foo2,O=Organization 2\\, inc.,C=SE", cli.getOut().toString().contains("CN=foo2,O=Organization 2\\, inc.,C=SE"));

            assertPrinted("prints new rule 1 with CERTIFICATE_SERIALNO", cli.getOut(), "CERTIFICATE_SERIALNO");
            assertPrinted("prints new rule 1 with 123456", cli.getOut(), "123456");
            assertPrinted("prints new rule 1 with CN=ManagementCA2,OU=Testing,C=SE", cli.getOut(), "CN=ManagementCA2,OU=Testing,C=SE");
            assertPrinted("prints new rule 1 with Other description", cli.getOut(), "Other description");
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }

    /**
     * Test adding and listing an auth rule.
     *
     * @param matchSubjectWithType The subject match type to use
     * @param expected The expected printout when adding and listing the role
     * @param expectDuplicate True if it is expected to show a warning of multiple
     *                        fields found in the cert
     */
    private void testAddFromCertWithMatchType(final String matchSubjectWithType,
                                              final String expected,
                                              boolean expectDuplicate)
            throws Exception {
        try {
            final String certPath =
                    getSignServerHome().getAbsolutePath() + File.separator +
                    "res" + File.separator + "test" + File.separator +
                    "dss10" + File.separator + "dss10_client1.pem";

            test.addCMSSigner1();
            assertEquals("execute add", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-add",
                    "-matchSubjectWithType", matchSubjectWithType,
                    "-matchIssuerWithType", "ISSUER_DN_BCSTYLE",
                    "-cert", certPath,
                    "-description", "Description"));
            if (expectDuplicate) {
                assertPrinted("warning message", cli.getOut(),
                              "More than one component matching " +
                              matchSubjectWithType + ", picking the first one");
            } else {
                assertNotPrinted("warning message", cli.getOut(),
                                 "More than one component matching " +
                                 matchSubjectWithType + ", picking the first one");
            }

            assertPrintedLitterally("prints new rule", cli.getOut(), expected);

            assertEquals("execute list", 0, cli.execute("authorizedclients",
                    "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrintedLitterally("prints new rule", cli.getOut(), expected);
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }

    /**
     * Test adding an authorization rule matching on subject serial number
     * by specifying a certificate.
     */
    @Test
    public void testAddFromCertWithSubjectTypeCERTIFICATE_SERIALNO() throws Exception {
        LOG.info("testAddFromCertWithSubjectTypeCERTIFICATE_SERIALNO");
        testAddFromCertWithMatchType("CERTIFICATE_SERIALNO",
                "CERTIFICATE_SERIALNO: 7577817a5a5199add001ee0edf4db3a3a139bfdd | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description",
                false);
    }

    /**
     * Test adding an authorization rule matching on subject DN CN field
     * by specifying a certificate.
     */
    @Test
    public void testAddFromCertWithSubjectTypeSUBJECT_RDN_CN() throws Exception {
        LOG.info("testAddFromCertWithSubjectTypeSUBJECT_RDN_CN");
        testAddFromCertWithMatchType("SUBJECT_RDN_CN",
                "SUBJECT_RDN_CN: Client 1 | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description",
                false);
    }

    /**
     * Test adding an authorization rule matching on subject DN DC field
     * by specifying a certificate.
     */
    @Test
    public void testAddFromCertWithSubjectTypeSUBJECT_RDN_DC() throws Exception {
        LOG.info("testAddFromCertWithSubjectTypeSUBJECT_RDN_DC");
        testAddFromCertWithMatchType("SUBJECT_RDN_DC",
                "SUBJECT_RDN_DC: primekey.com | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description",
                false);
    }

    /**
     * Test adding an authorization rule matching on subject DN ST field
     * by specifying a certificate.
     */
    @Test
    public void testAddFromCertWithSubjectTypeSUBJECT_RDN_ST() throws Exception {
        LOG.info("testAddFromCertWithSubjectTypeSUBJECT_RDN_ST");
        testAddFromCertWithMatchType("SUBJECT_RDN_ST",
                "SUBJECT_RDN_ST: Stockholm | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description",
                false);
    }

    /**
     * Test adding an authorization rule matching on subject DN L field
     * by specifying a certificate.
     */
    @Test
    public void testAddFromCertWithSubjectTypeSUBJECT_RDN_L() throws Exception {
        LOG.info("testAddFromCertWithSubjectTypeSUBJECT_RDN_L");
        testAddFromCertWithMatchType("SUBJECT_RDN_L",
                "SUBJECT_RDN_L: Solna | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description",
                false);
    }

    /**
     * Test adding an authorization rule matching on subject DN O field
     * by specifying a certificate.
     */
    @Test
    public void testAddFromCertWithSubjectTypeSUBJECT_RDN_O() throws Exception {
        LOG.info("testAddFromCertWithSubjectTypeSUBJECT_RDN_O");
        testAddFromCertWithMatchType("SUBJECT_RDN_O",
                "SUBJECT_RDN_O: PrimeKey | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description",
                false);
    }

    /**
     * Test adding an authorization rule matching on subject DN OU field
     * by specifying a certificate.
     */
    @Test
    public void testAddFromCertWithSubjectTypeSUBJECT_RDN_OU() throws Exception {
        LOG.info("testAddFromCertWithSubjectTypeSUBJECT_RDN_OU");
        testAddFromCertWithMatchType("SUBJECT_RDN_OU",
                "SUBJECT_RDN_OU: SignServer Testing | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description",
                false);
    }

    /**
     * Test adding an authorization rule matching on subject DN TITLE field
     * by specifying a certificate.
     */
    @Test
    public void testAddFromCertWithSubjectTypeSUBJECT_RDN_TITLE() throws Exception {
        LOG.info("testAddFromCertWithSubjectTypeSUBJECT_RDN_TILE");
        testAddFromCertWithMatchType("SUBJECT_RDN_TITLE",
                "SUBJECT_RDN_TITLE: All Fields End Entity | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description",
                false);
    }

    /**
     * Test adding an authorization rule matching on subject DN UID field
     * by specifying a certificate.
     */
    @Test
    public void testAddFromCertWithSubjectTypeSUBJECT_RDN_UID() throws Exception {
        LOG.info("testAddFromCertWithSubjectTypeSUBJECT_RDN_UID");
        testAddFromCertWithMatchType("SUBJECT_RDN_UID",
                "SUBJECT_RDN_UID: 123123123 | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description",
                false);
    }

    /**
     * Test adding an authorization rule matching on subject SAN SUBJECT_ALTNAME_RFC822NAME field
     * by specifying a certificate.
     */
    @Test
    public void testAddFromCertWithSubjectTypeSUBJECT_ALTNAME_RFC822NAME() throws Exception {
        LOG.info("testAddFromCertWithSubjectTypeSUBJECT_ALTNAME_RFC822NAME");
        testAddFromCertWithMatchType("SUBJECT_ALTNAME_RFC822NAME",
                "SUBJECT_ALTNAME_RFC822NAME: noreply@primekey.com | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description",
                false);
    }

    /**
     * Test adding an authorization rule matching on subject SAN SUBJECT_ALTNAME_MSUPN field
     * by specifying a certificate.
     */
    @Test
    public void testAddFromCertWithSubjectTypeSUBJECT_ALTNAME_MSUPN() throws Exception {
        LOG.info("testAddFromCertWithSubjectTypeSUBJECT_ALTNAME_MSUPN");
        testAddFromCertWithMatchType("SUBJECT_ALTNAME_MSUPN",
                "SUBJECT_ALTNAME_MSUPN: myupn@example.org | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description",
                false);
    }

    /**
     * Test adding an authorization rule matching on subject SAN SUBJECT_ALTNAME_MSUPN field
     * by specifying a certificate.
     */
    @Test
    public void testAddFromCertWithSubjectTypeSUBJECT_RDN_SERIALNO() throws Exception {
        LOG.info("testAddFromCertWithSubjectTypeSUBJECT_RDN_SERIALNO");
        testAddFromCertWithMatchType("SUBJECT_RDN_SERIALNO",
                "SUBJECT_RDN_SERIALNO: 123-4567abc | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description",
                true);
    }

    /**
     * Test adding an authorization rule matching on subject DN field not present
     * in the certificate
     */
    @Test
    public void testAddFromCertWithNonExistingDNField() throws Exception {
        LOG.info("testAddFromCertWithNonExistingDNField");
        try {
            final String certPath =
                    getSignServerHome().getAbsolutePath() + File.separator +
                    "res" + File.separator + "test" + File.separator +
                    "dss10" + File.separator + "DSSSubCA11.cacert.pem";

            test.addCMSSigner1();
            assertEquals("execute add", -2, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-add",
                    "-matchSubjectWithType", "SUBJECT_RDN_SERIALNO",
                    "-matchIssuerWithType", "ISSUER_DN_BCSTYLE",
                    "-cert", certPath,
                    "-description", "Description"));
            assertPrinted("error message", cli.getOut(), "DN field SUBJECT_RDN_SERIALNO not found in subject DN of certificate");

            assertEquals("execute list", 0, cli.execute("authorizedclients",
                    "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrinted("prints no auth clients", cli.getOut(), "No authorized clients exists.");
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }

    /**
     * Test adding an authorization rule matching on subject serial number
     * by specifying a certificate and then remove the same role.
     */
    @Test
    public void testAddFromCertAndRemove() throws Exception {
        LOG.info("testAddFromCertWithSubjectTypeCERTIFICATE_SERIALNO");
        try {
            final String certPath =
                    getSignServerHome().getAbsolutePath() + File.separator +
                    "res" + File.separator + "test" + File.separator +
                    "dss10" + File.separator + "DSSSubCA11.cacert.pem";

            test.addCMSSigner1();
            assertEquals("execute add", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-add",
                    "-matchSubjectWithType", "CERTIFICATE_SERIALNO",
                    "-matchIssuerWithType", "ISSUER_DN_BCSTYLE",
                    "-cert", certPath,
                    "-description", "Description"));
            assertPrinted("prints new rule", cli.getOut(), "CERTIFICATE_SERIALNO: 3519c898bfef0d7e | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description");

            assertEquals("execute list", 0, cli.execute("authorizedclients",
                    "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrinted("prints new rule", cli.getOut(), "CERTIFICATE_SERIALNO: 3519c898bfef0d7e | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: Description");

            assertEquals("execute remove", 0, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-remove",
                    "-matchSubjectWithType", "CERTIFICATE_SERIALNO",
                    "-matchIssuerWithType", "ISSUER_DN_BCSTYLE",
                    "-cert", certPath,
                    "-description", "Description"));
            assertPrinted("prints rule", cli.getOut(), "SUBJECT_RDN_CN: DSS Sub CA 11 | ISSUER_DN_BCSTYLE: CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE | Description: my rule");
            assertPrinted("prints removed", cli.getOut(), "Rule removed");

            assertEquals("execute list", 0, cli.execute("authorizedclients",
                    "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertPrinted("prints empty", cli.getOut(), "No authorized clients exists.");
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }

    /**
     * Test adding a rule from a certificate specifying a field that is not
     * existing in the subject DN.
     */
    @Test
    public void testAddFromCertWithNonExistingField() throws Exception {
        try {
            final String certPath =
                    getSignServerHome().getAbsolutePath() + File.separator +
                    "res" + File.separator + "test" + File.separator +
                    "dss10" + File.separator + "DSSSubCA11.cacert.pem";

            test.addCMSSigner1();
            assertEquals("execute add", -2, cli.execute("authorizedclients", "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-add",
                    "-matchSubjectWithType", "SUBJECT_RDN_TITLE",
                    "-matchIssuerWithType", "ISSUER_DN_BCSTYLE",
                    "-cert", certPath,
                    "-description", "Description"));

            assertPrintedLitterally("prints not found", cli.getOut(),
                    "DN field SUBJECT_RDN_TITLE not found in subject DN of certificate");

            assertEquals("execute list", 0, cli.execute("authorizedclients",
                    "-worker", String.valueOf(test.getSignerIdCMSSigner1()),
                    "-list"));
            assertNotPrinted("does not mention new rule", cli.getOut(), "SUBJECT_RDN_TITLE");
        } finally {
            test.removeWorker(test.getSignerIdCMSSigner1());
        }
    }
}
