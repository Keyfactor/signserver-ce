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
import java.io.FileInputStream;
import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TimeStampResponse;
import org.signserver.client.TimeStampClient;
import org.signserver.testutils.ExitException;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/** 
 * Class used to test the basic aspects of the SignServer CLI related to 
 * archiving.
 * 
 * Notice: Tests in this file assumes archiving to be enabled (ie. not running 
 * without database). If running without database this test case should not be 
 * included in the test run.
 * 
 * @version $Id$
 */
public class ArchivingCLITest extends ModulesTestCase {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignServerCLITest.class);
    
    private static final String TESTTSID = "1000";

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }
    
    /**
     * Tests archiving commands for timestamp token.
     */
    public void testSetupTimeStamp() throws Exception {
        LOG.debug(">testSetupTimeStamp");

        assertTrue(new File(getSignServerHome() + "/src/test/test_add_timestamp_archive_configuration.properties").exists());
        TestUtils.assertSuccessfulExecution(new String[]{"setproperties",
                    getSignServerHome() + "/src/test/test_add_timestamp_archive_configuration.properties"});
        assertTrue(TestUtils.grepTempOut("Setting the property NAME to timestampSigner1000 for worker 1000"));


        TestUtils.assertSuccessfulExecution(new String[]{"reload",
                    "1000"});
        
        // Test the timestamp client
        try {
            TestUtils.flushTempOut();
            TimeStampClient.main(new String[]{
                        "http://localhost:8080/signserver/process?workerId=" + TESTTSID,
                        "-instr",
                        "TEST",
                        "-outrep",
                        getSignServerHome() + "/tmp/timestamptest.data"});

            FileInputStream fis = new FileInputStream(getSignServerHome() + "/tmp/timestamptest.data");
            TimeStampResponse tsr = new TimeStampResponse(fis);
            assertTrue(tsr != null);
            String archiveId = tsr.getTimeStampToken().getTimeStampInfo().getSerialNumber().toString(16);
            assertNotNull(archiveId);

            TestUtils.assertSuccessfulExecution(new String[]{"archive",
                        "findfromarchiveid",
                        TESTTSID,
                        archiveId,
                        getSignServerHome() + "/tmp"});
            File datafile = new File(getSignServerHome() + "/tmp/" + archiveId);
            assertTrue(datafile.exists());
            datafile.delete();
            TestUtils.assertSuccessfulExecution(new String[]{"archive",
                        "findfromrequestip",
                        TESTTSID,
                        "127.0.0.1",
                        getSignServerHome() + "/tmp"});
            datafile = new File(getSignServerHome() + "/tmp/" + archiveId);
            assertTrue(datafile.exists());


        } catch (ExitException e) {
            TestUtils.printTempErr();
            TestUtils.printTempOut();
            assertTrue(false);
        }

        TestingSecurityManager.remove();
    }
    
    public void testRemoveTimeStamp() throws Exception {
        LOG.debug(">testRemoveTimeStamp");
        // Remove and restore
        TestUtils.assertSuccessfulExecution(new String[]{"setproperties",
                    getSignServerHome() + "/src/test/test_rem_timestamp_configuration.properties"});
        assertTrue(TestUtils.grepTempOut("Removing the property NAME  for worker 1000"));

        TestUtils.assertSuccessfulExecution(new String[]{"getconfig",
                    TESTTSID});
        assertFalse(TestUtils.grepTempOut("NAME=timestampSigner1000"));

        TestUtils.assertSuccessfulExecution(new String[]{"removeproperty",
                    TESTTSID,
                    "TESTKEY"});

        TestUtils.assertSuccessfulExecution(new String[]{"reload",
                    TESTTSID});
        assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));

        TestingSecurityManager.remove();
    }
}
