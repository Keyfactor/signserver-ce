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
import org.signserver.client.cli.defaultimpl.TimeStampCommand;
import org.signserver.testutils.CLITestHelper;
import static org.signserver.testutils.CLITestHelper.assertNotPrinted;
import static org.signserver.testutils.CLITestHelper.assertPrinted;
import org.signserver.testutils.ModulesTestCase;

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

    private CLITestHelper cli = getAdminCLI();
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }
    
    /**
     * Tests archiving commands for timestamp token.
     */
    public void testSetupTimeStamp() throws Exception {
        LOG.debug(">testSetupTimeStamp");

        assertTrue(new File(getSignServerHome() + "/res/test/test_add_timestamp_archive_configuration.properties").exists());
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("setproperties", getSignServerHome() + "/res/test/test_add_timestamp_archive_configuration.properties"));
        assertPrinted("", cli.getOut(), "Setting the property NAME to timestampSigner1000 for worker 1000");
        
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("removeproperty", TESTTSID, "ARCHIVER0.ARCHIVE_OF_TYPE"));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("reload", "1000"));
        
        // Test the timestamp client
        TimeStampCommand cmd = new TimeStampCommand();
        assertEquals(CommandLineInterface.RETURN_SUCCESS, 
                cmd.execute("http://localhost:8080/signserver/process?workerId=" + TESTTSID,
                    "-instr",
                    "TEST",
                    "-outrep",
                    getSignServerHome() + "/tmp/timestamptest.data"));

        FileInputStream fis = new FileInputStream(getSignServerHome() + "/tmp/timestamptest.data");
        TimeStampResponse tsr = new TimeStampResponse(fis);
        assertTrue(tsr != null);
        String archiveId = tsr.getTimeStampToken().getTimeStampInfo().getSerialNumber().toString(16);
        assertNotNull(archiveId);

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, cli.execute("archive",
                    "findfromarchiveid",
                    TESTTSID,
                    archiveId,
                    getSignServerHome() + "/tmp"));
        File datafile = new File(getSignServerHome() + "/tmp/" + archiveId + ".response");
        assertTrue(datafile.exists());
        datafile.delete();
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, cli.execute("archive",
                    "findfromrequestip",
                    TESTTSID,
                    "127.0.0.1",
                    getSignServerHome() + "/tmp"));
        datafile = new File(getSignServerHome() + "/tmp/" + archiveId + ".response");
        assertTrue(datafile.exists());
    }
    
    /**
     * Tests archiving commands for timestamping with both request and response
     * archived.
     */
    public void testArchiveRequestAndResponse() throws Exception {
        LOG.debug(">testSetupTimeStamp");

        assertTrue(new File(getSignServerHome() + "/res/test/test_add_timestamp_archive_configuration.properties").exists());
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("setproperties", getSignServerHome() + "/res/test/test_add_timestamp_archive_configuration.properties"));
        assertPrinted("", cli.getOut(), "Setting the property NAME to timestampSigner1000 for worker 1000");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("setproperty", TESTTSID, "ARCHIVER0.ARCHIVE_OF_TYPE", "REQUEST_AND_RESPONSE"));
        
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("reload", "1000"));
        
        // Test the timestamp client
        TimeStampCommand cmd = new TimeStampCommand();
        assertEquals(CommandLineInterface.RETURN_SUCCESS, 
                cmd.execute("http://localhost:8080/signserver/process?workerId=" + TESTTSID,
                    "-instr",
                    "TEST",
                    "-outrep",
                    getSignServerHome() + "/tmp/timestamptest.data"));

        FileInputStream fis = new FileInputStream(getSignServerHome() + "/tmp/timestamptest.data");
        TimeStampResponse tsr = new TimeStampResponse(fis);
        assertTrue(tsr != null);
        String archiveId = tsr.getTimeStampToken().getTimeStampInfo().getSerialNumber().toString(16);
        assertNotNull(archiveId);

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, cli.execute("archive",
                    "findfromarchiveid",
                    TESTTSID,
                    archiveId,
                    getSignServerHome() + "/tmp"));
        File datafileResponse = new File(getSignServerHome() + "/tmp/" + archiveId + ".response");
        File datafileRequest = new File(getSignServerHome() + "/tmp/" + archiveId + ".request");
        assertTrue(datafileResponse.exists());
        datafileResponse.delete();
        assertTrue(datafileRequest.exists());
        datafileRequest.delete();
        
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, cli.execute("archive",
                    "findfromrequestip",
                    TESTTSID,
                    "127.0.0.1",
                    getSignServerHome() + "/tmp"));
        datafileResponse = new File(getSignServerHome() + "/tmp/" + archiveId + ".response");
        datafileRequest = new File(getSignServerHome() + "/tmp/" + archiveId + ".request");
        assertTrue(datafileResponse.exists());
        assertTrue(datafileRequest.exists());
    }
    
    public void testRemoveTimeStamp() throws Exception {
        LOG.debug(">testRemoveTimeStamp");
        // Remove and restore
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("setproperties", getSignServerHome() + "/res/test/test_rem_timestamp_configuration.properties"));
        assertPrinted("", cli.getOut(), "Removing the property NAME  for worker 1000");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("getconfig", TESTTSID));
        assertNotPrinted("", cli.getOut(), "NAME=timestampSigner1000");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("removeproperty", TESTTSID, "TESTKEY"));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("reload", TESTTSID));
        assertPrinted("", cli.getOut(), "SignServer reloaded successfully");
    }
}
