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
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

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
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ArchivingCLITest extends ModulesTestCase {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignServerCLITest.class);
    
    private static final int WORKERID = 1000;
    private static final String TESTTSID = String.valueOf(WORKERID);

    private CLITestHelper cli = getAdminCLI();

    
    /**
     * Tests archiving commands for timestamp token.
     */
    @Test
    public void test01SetupTimeStamp() throws Exception {
        LOG.info("test01SetupTimeStamp");
    
        assertTrue(new File(getSignServerHome() + "/res/test/test_add_timestamp_archive_configuration.properties").exists());
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("setproperties", getSignServerHome() + "/res/test/test_add_timestamp_archive_configuration.properties"));
        assertPrinted("", cli.getOut(), "Setting the property NAME to timestampSigner1000 for worker 1000");
        
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", TESTTSID, "KEYSTOREPATH",
                        getSignServerHome() + "/res/test/dss10/dss10_tssigner1.p12"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", TESTTSID, "KEYSTORETYPE", "PKCS12"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", TESTTSID, "KEYSTOREPASSWORD", "foo123"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", TESTTSID, "DEFAULTKEY", "TS Signer 1"));
       
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
    
        // clean up for before running the query command
        datafile.delete();
        
        // test query command
        assertEquals("Command status", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("archive", "query", "-limit", "10",
                            "-criteria", "signerid EQ " + TESTTSID,
                            "-criteria", "archiveid EQ " + archiveId));
        assertPrinted("", cli.getOut(), archiveId + ", ");
        // running without -outpath should NOT result in dumping the data
        assertTrue("Should not write archive data", !datafile.exists());
        
        assertEquals("Command status", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("archive", "query", "-limit", "10",
                            "-criteria", "signerid EQ " + TESTTSID,
                            "-criteria", "requestIP EQ 127.0.0.1"));
        assertPrinted("", cli.getOut(), "REQUEST, " + TESTTSID + ", , , 127.0.0.1");
    
        // test running the query command with outputting data
         assertEquals("Command status", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("archive", "query", "-limit", "10",
                            "-criteria", "signerid EQ " + TESTTSID,
                            "-criteria", "archiveid EQ " + archiveId,
                            "-outpath", getSignServerHome() + "/tmp"));
        assertPrinted("", cli.getOut(), archiveId + ", ");
        assertPrinted("", cli.getOut(), "Downloaded 1 archive entries");
        // running without -outpath should NOT result in dumping the data
        assertTrue("Should write archive data", datafile.exists());
    
        // clean up temp file
        datafile.delete();
    }
    
    /**
     * Tests archiving commands for timestamping with both request and response
     * archived.
     */
    @Test
    public void test01ArchiveRequestAndResponse() throws Exception {
        LOG.info("test01ArchiveRequestAndResponse");

        assertTrue(new File(getSignServerHome() + "/res/test/test_add_timestamp_archive_configuration.properties").exists());
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("setproperties", getSignServerHome() + "/res/test/test_add_timestamp_archive_configuration.properties"));
        assertPrinted("", cli.getOut(), "Setting the property NAME to timestampSigner1000 for worker 1000");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", TESTTSID, "KEYSTOREPATH",
                        getSignServerHome() + "/res/test/dss10/dss10_tssigner1.p12"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", TESTTSID, "KEYSTORETYPE", "PKCS12"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", TESTTSID, "KEYSTOREPASSWORD", "foo123"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", TESTTSID, "DEFAULTKEY", "TS Signer 1"));
        
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
        
        // clean up before running the query command
        datafileResponse.delete();
        datafileRequest.delete();

        // test query command
        assertEquals("Command status", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("archive", "query", "-limit", "10",
                            "-criteria", "signerid EQ " + TESTTSID,
                            "-criteria", "archiveid EQ " + archiveId));
        assertPrinted("", cli.getOut(), archiveId + ", ");
        
        assertEquals("Command status", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("archive", "query", "-limit", "10",
                            "-criteria", "signerid EQ " + TESTTSID,
                            "-criteria", "requestIP EQ 127.0.0.1"));
        assertPrinted("", cli.getOut(), "REQUEST, " + TESTTSID + ", , , 127.0.0.1");
        assertPrinted("", cli.getOut(), "RESPONSE, " + TESTTSID + ", , , 127.0.0.1");
        
        assertEquals("Command status", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("archive", "query", "-limit", "10",
                            "-criteria", "signerid EQ " + TESTTSID,
                            "-criteria", "archiveid EQ " + archiveId,
                            "-outpath", getSignServerHome() + "/tmp"));
        assertPrinted("", cli.getOut(), "REQUEST, " + TESTTSID + ", , , 127.0.0.1");
        assertPrinted("", cli.getOut(), "RESPONSE, " + TESTTSID + ", , , 127.0.0.1");
        assertPrinted("", cli.getOut(), "Downloaded 2 archive entries");
        assertTrue("Should write request", datafileRequest.exists());
        assertTrue("Should write response", datafileResponse.exists());
        
        // clean up temp files
        datafileRequest.delete();
        datafileResponse.delete();
    }
    
    @Test
    public void test01RemoveTimeStamp() throws Exception {
        LOG.info("test01RemoveTimeStamp");
        try {
            // Remove and restore
            assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                    cli.execute("setproperties", getSignServerHome() + "/res/test/test_rem_timestamp_configuration.properties"));
            assertPrinted("", cli.getOut(), "Removing the property NAME  for worker 1000");

            assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                    cli.execute("getconfig", TESTTSID));
            assertNotPrinted("", cli.getOut(), "AUTHTYPE=NOAUTH");

            assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                    cli.execute("removeproperty", TESTTSID, "TESTKEY"));

            assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                    cli.execute("reload", TESTTSID));
            assertPrinted("", cli.getOut(), "SignServer reloaded successfully");
        } finally {
            removeWorker(WORKERID);
        }
    }
    
    @Test
    public void test99TearDownDatabase() throws Exception {
        LOG.info("test99TearDownDatabase");
        removeWorker(WORKERID);
    }
}
