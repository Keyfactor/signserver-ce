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
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

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
public class GroupKeyServiceCLITest extends ModulesTestCase {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignServerCLITest.class);
    
    private static final String TESTGSID = "1023";
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }
    
    public void testSetupGroupKeyService() throws Exception {
        TestUtils.assertSuccessfulExecution(new String[]{"reload",
                    "all"});

        assertTrue(new File(getSignServerHome() + "/src/test/test_add_groupkeyservice_configuration.properties").exists());
        TestUtils.assertSuccessfulExecution(new String[]{"setproperties",
                    getSignServerHome() + "/src/test/test_add_groupkeyservice_configuration.properties"});
        assertTrue(TestUtils.grepTempOut("Setting the property NAME to Test1 for worker 1023"));

        TestUtils.assertSuccessfulExecution(new String[]{"reload",
                    TESTGSID});

        TestUtils.assertSuccessfulExecution(new String[]{"getstatus",
                    "complete",
                    TESTGSID});

        TestUtils.assertSuccessfulExecution(new String[]{"groupkeyservice",
                    "switchenckey", "" + TESTGSID});
        assertTrue(TestUtils.grepTempOut("key switched successfully"));
        TestUtils.assertSuccessfulExecution(new String[]{"groupkeyservice",
                    "switchenckey", "Test1"});
        assertTrue(TestUtils.grepTempOut("key switched successfully"));

        TestUtils.assertSuccessfulExecution(new String[]{"groupkeyservice",
                    "pregeneratekeys", "" + TESTGSID, "1"});
        assertTrue(TestUtils.grepTempOut("1 Pregenerated successfully"));

        TestUtils.assertSuccessfulExecution(new String[]{"groupkeyservice",
                    "pregeneratekeys", "" + TESTGSID, "101"});
        assertTrue(TestUtils.grepTempOut("101 Pregenerated successfully"));

        TestUtils.assertSuccessfulExecution(new String[]{"groupkeyservice",
                    "pregeneratekeys", "" + TESTGSID, "1000"});
        assertTrue(TestUtils.grepTempOut("1000 Pregenerated successfully"));

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        String startDate = dateFormat.format(new Date(0));
        String endDate = dateFormat.format(new Date(System.currentTimeMillis() + 120000));

        TestUtils.assertSuccessfulExecution(new String[]{"groupkeyservice",
                    "removegroupkeys", "" + TESTGSID, "created", startDate, endDate});
        assertTrue(TestUtils.grepTempOut("1102 Group keys removed"));

        TestUtils.assertSuccessfulExecution(new String[]{"groupkeyservice",
                    "removegroupkeys", "" + TESTGSID, "FIRSTUSED", startDate, endDate});
        assertTrue(TestUtils.grepTempOut("0 Group keys removed"));

        TestUtils.assertSuccessfulExecution(new String[]{"groupkeyservice",
                    "removegroupkeys", "" + TESTGSID, "LASTFETCHED", startDate, endDate});
        assertTrue(TestUtils.grepTempOut("0 Group keys removed"));

        TestingSecurityManager.remove();
    }
        
    public void testRemoveGroupKeyService() {
        // Remove and restore
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker",
                    "Test1"});
        assertTrue(TestUtils.grepTempOut("Property 'NAME' removed"));

        TestUtils.assertSuccessfulExecution(new String[]{"reload",
                    TESTGSID});
        assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));

        TestingSecurityManager.remove();
    }
}
