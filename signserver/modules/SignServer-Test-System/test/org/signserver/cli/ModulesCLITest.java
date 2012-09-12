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
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/** 
 * Class used to test the basic aspects of the SignServer CLI related to 
 * cluster class loading.
 * 
 * Notice: Tests in this file assumes cluster class loader to be enabled (ie. not running 
 * without database). If running without database this test case should not be 
 * included in the test run.
 * 
 * @version $Id$
 */
public class ModulesCLITest extends ModulesTestCase {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignServerCLITest.class);
    
    private static final String TESTTSID = "1000";

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }
    
        public void testSetupModules() throws Exception {

        TestUtils.assertSuccessfulExecution(new String[]{"module", "add",
                    getSignServerHome() + "/src/test/testmodule-withoutdescr.mar"});
        assertTrue(TestUtils.grepTempOut("Loading module TESTMODULE-WITHOUTDESCR with version 1"));
        assertTrue(TestUtils.grepTempOut("Module loaded successfully."));

        TestUtils.assertSuccessfulExecution(new String[]{"module", "add",
                    getSignServerHome() + "/src/test/testmodule-withdescr.mar"});

        assertTrue(TestUtils.grepTempOut("Loading module TESTMODULE-WITHDESCR with version 2"));
        assertTrue(TestUtils.grepTempOut("Module loaded successfully."));
        assertTrue(TestUtils.grepTempOut("Setting the property ENV to PROD for worker 4321"));

        TestUtils.assertSuccessfulExecution(new String[]{"module", "add",
                    getSignServerHome() + "/src/test/testmodule-withdescr.mar", "devel"});
        assertTrue(TestUtils.grepTempOut("Setting the property ENV to DEVEL for worker 3433"));

        TestUtils.assertSuccessfulExecution(new String[]{"module", "list"});

        assertTrue(TestUtils.grepTempOut("Module : TESTMODULE-WITHDESCR, version 2"));
        assertTrue(TestUtils.grepTempOut("part1"));
        assertTrue(TestUtils.grepTempOut("part2"));
        assertTrue(TestUtils.grepTempOut("Module : TESTMODULE-WITHOUTDESCR, version 1"));
        assertTrue(TestUtils.grepTempOut("server"));
        assertFalse(TestUtils.grepTempOut(".jar"));

        TestUtils.assertSuccessfulExecution(new String[]{"module", "list", "showjars"});

        assertTrue(TestUtils.grepTempOut("Module : TESTMODULE-WITHDESCR, version 2"));
        assertTrue(TestUtils.grepTempOut("part1"));
        assertTrue(TestUtils.grepTempOut("part2"));
        assertTrue(TestUtils.grepTempOut("Module : TESTMODULE-WITHOUTDESCR, version 1"));
        assertTrue(TestUtils.grepTempOut("server"));
        assertTrue(TestUtils.grepTempOut("testjar.jar"));
        assertTrue(TestUtils.grepTempOut("testjar2.jar"));

        TestingSecurityManager.remove();
    }

    public void testremoves() {
        // Remove and restore

        TestUtils.assertSuccessfulExecution(new String[]{"module", "remove",
                    "testmodule-withoutdescr", "1"});
        assertTrue(TestUtils.grepTempOut("Removing module TESTMODULE-WITHOUTDESCR version 1"));
        assertTrue(TestUtils.grepTempOut("Removal of module successful."));

        TestUtils.assertSuccessfulExecution(new String[]{"module", "remove",
                    "testmodule-withdescr", "2"});
        assertTrue(TestUtils.grepTempOut("Removing module TESTMODULE-WITHDESCR version 2"));
        assertTrue(TestUtils.grepTempOut("Removal of module successful."));

        TestUtils.assertSuccessfulExecution(new String[]{"removeworker",
                    "6543"});

        TestUtils.assertSuccessfulExecution(new String[]{"removeworker",
                    "4321"});

        TestUtils.assertSuccessfulExecution(new String[]{"removeworker",
                    "3433"});

        TestingSecurityManager.remove();
    }
}
