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
import java.text.SimpleDateFormat;
import java.util.Date;
import org.apache.log4j.Logger;
import org.signserver.testutils.CLITestHelper;
import static org.signserver.testutils.CLITestHelper.assertPrinted;
import org.signserver.testutils.ModulesTestCase;
import static org.junit.Assert.*;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/** 
 * Class used to test the basic aspects of the SignServer CLI related to 
 * archiving.
 * 
 * Notice: Tests in this file assumes group key service to be enabled (ie. not running 
 * without database). If running without database this test case should not be 
 * included in the test run.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class GroupKeyServiceCLITest extends ModulesTestCase {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignServerCLITest.class);
    
    private static final String TESTGSID = "1023";

    private CLITestHelper cli = getAdminCLI();
    
    @Test
    public void test01SetupGroupKeyService() throws Exception {
        LOG.debug(">testSetupGroupKeyService");
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("reload", "all"));

        assertTrue(new File(getSignServerHome() + "/res/test/test_add_groupkeyservice_configuration.properties").exists());
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("setproperties", getSignServerHome() + "/res/test/test_add_groupkeyservice_configuration.properties"));
        assertPrinted("", cli.getOut(), "Setting the property NAME to Test1 for worker 1023");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("reload", TESTGSID));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("getstatus", "complete", TESTGSID));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("groupkeyservice", "switchenckey", "" + TESTGSID));
        assertPrinted("", cli.getOut(), "key switched successfully");
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("groupkeyservice", "switchenckey", "Test1"));
        assertPrinted("", cli.getOut(), "key switched successfully");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("groupkeyservice", "pregeneratekeys", "" + TESTGSID, "1"));
        assertPrinted("", cli.getOut(), "1 Pregenerated successfully");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("groupkeyservice", "pregeneratekeys", "" + TESTGSID, "101"));
        assertPrinted("", cli.getOut(), "101 Pregenerated successfully");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("groupkeyservice", "pregeneratekeys", "" + TESTGSID, "1000"));
        assertPrinted("", cli.getOut(), "1000 Pregenerated successfully");

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        String startDate = dateFormat.format(new Date(0));
        String endDate = dateFormat.format(new Date(System.currentTimeMillis() + 120000));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("groupkeyservice", "removegroupkeys", "" + TESTGSID, "created", startDate, endDate));
        assertPrinted("", cli.getOut(), "1102 Group keys removed");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("groupkeyservice", "removegroupkeys", "" + TESTGSID, "FIRSTUSED", startDate, endDate));
        assertPrinted("", cli.getOut(), "0 Group keys removed");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("groupkeyservice", "removegroupkeys", "" + TESTGSID, "LASTFETCHED", startDate, endDate));
        assertPrinted("", cli.getOut(), "0 Group keys removed");
    }

    @Test
    public void test02RemoveGroupKeyService() throws Exception {
        LOG.debug(">testRemoveGroupKeyService");
        // Remove and restore
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("removeworker", "Test1"));
        assertPrinted("", cli.getOut(), "Property 'NAME' removed");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("reload", TESTGSID));
        assertPrinted("", cli.getOut(), "SignServer reloaded successfully");
    }
}
