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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.util.Properties;

import org.bouncycastle.tsp.TimeStampResponse;
import org.signserver.client.TimeStampClient;
import org.signserver.client.cli.DocumentSignerCLI;
import org.signserver.testutils.ExitException;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Class used to test the basic aspects of the SignServer CLI such
 * as get status, activate, set properties etc..
 * 
 * @author Philip Vendil 21 okt 2007
 * @version $Id$
 */
public class SignServerCLITest extends ModulesTestCase {

    private static final String TESTID = "100";
    private static final String TESTTSID = "1000";
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();

        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
        TestingSecurityManager.install();
    }

    public void testBasicSetup() throws Exception {

        TestUtils.assertFailedExecution(new String[]{"noarguments"});
        assertTrue(TestUtils.grepTempOut("Usage: signserver"));


        TestUtils.assertSuccessfulExecution(new String[]{"setproperty",
                    "global",
                    "WORKER" + TESTID + ".CLASSPATH",
                    "org.signserver.server.signers.TimeStampSigner"});

        TestUtils.assertSuccessfulExecution(new String[]{"getconfig",
                    "global"});

        assertTrue(TestUtils.grepTempOut("WORKER" + TESTID + ".CLASSPATH"));

        TestUtils.assertSuccessfulExecution(new String[]{"setproperty",
                    TESTID,
                    "TESTKEY",
                    "TESTVALUE"});

        TestUtils.assertSuccessfulExecution(new String[]{"getconfig",
                    TESTID});

        assertTrue(TestUtils.grepTempOut("TESTKEY"));

        TestUtils.assertSuccessfulExecution(new String[]{"removeproperty",
                    "" + TESTID,
                    "TESTKEY"});
        TestUtils.assertSuccessfulExecution(new String[]{"removeproperty",
                    "global",
                    "WORKER" + TESTID + ".CLASSPATH"});

        TestUtils.assertSuccessfulExecution(new String[]{"getconfig",
                    "global"});
        assertFalse(TestUtils.grepTempOut("WORKER" + TESTID + ".CLASSPATH"));

        TestUtils.assertSuccessfulExecution(new String[]{"getconfig",
                    "" + TESTID});
        assertFalse(TestUtils.grepTempOut("TESTKEY"));

        TestUtils.assertSuccessfulExecution(new String[]{"getconfig",
                    "-host",
                    "localhost",
                    "" + TESTID});
        TestingSecurityManager.remove();
    }

    public void testSetupTimeStamp() throws Exception {

        assertTrue(new File(getSignServerHome() + "/src/test/test_add_timestamp_configuration.properties").exists());
        TestUtils.assertSuccessfulExecution(new String[]{"setproperties",
                    getSignServerHome() + "/src/test/test_add_timestamp_configuration.properties"});
        assertTrue(TestUtils.grepTempOut("Setting the property NAME to timestampSigner1000 for worker 1000"));


        TestUtils.assertSuccessfulExecution(new String[]{"reload",
                    "1000"});

        TestUtils.assertSuccessfulExecution(new String[]{"getstatus",
                    "complete",
                    TESTTSID});

        TestUtils.assertSuccessfulExecution(new String[]{"setproperty",
                    TESTTSID,
                    "TESTKEY",
                    "TESTVALUE"});

        TestUtils.assertSuccessfulExecution(new String[]{"getstatus",
                    "complete",
                    TESTTSID});

        TestUtils.assertSuccessfulExecution(new String[]{"reload",
                    TESTTSID});
        assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));


        TestUtils.assertSuccessfulExecution(new String[]{"getstatus",
                    "complete",
                    TESTTSID});
        assertTrue(TestUtils.grepTempOut("NAME=timestampSigner1000"));
        assertTrue(TestUtils.grepTempOut("TESTKEY"));


        TestUtils.assertSuccessfulExecution(new String[]{"reload",
                    TESTTSID});
        assertTrue(TestUtils.grepTempOut("SignServer reloaded successfully"));


        TestUtils.assertSuccessfulExecution(new String[]{"getstatus",
                    "complete",
                    TESTTSID});
        assertTrue(TestUtils.grepTempOut("NAME=timestampSigner1000"));

        // Test token operations
        TestUtils.assertFailedExecution(new String[]{"activatesigntoken",
                    TESTTSID,
                    "9876"});
        TestUtils.assertSuccessfulExecution(new String[]{"activatesigntoken",
                    TESTTSID,
                    "1234"});
        assertTrue(TestUtils.grepTempOut("Activation of worker was successful"));


        TestUtils.assertSuccessfulExecution(new String[]{"deactivatesigntoken",
                    TESTTSID});
        assertTrue(TestUtils.grepTempOut("Deactivation of worker was successful"));


        // Test operations by name
        TestUtils.assertSuccessfulExecution(new String[]{"activatecryptotoken",
                    "timestampSigner1000",
                    "1234"});
        assertTrue(TestUtils.grepTempOut("Activation of worker was successful"));
        TestUtils.assertSuccessfulExecution(new String[]{"activatecryptotoken",
                    "TIMESTAMPSIGNER1000",
                    "1234"});
        TestUtils.assertFailedExecution(new String[]{"activatecryptotoken",
                    "TIMESTAMPSIGNER2000",
                    "1234"});

        // Test authorized clients
        TestUtils.assertSuccessfulExecution(new String[]{"addauthorizedclient",
                    "TIMESTAMPSIGNER1000",
                    "EF34242D2324",
                    "CN=Test Root CA"});
        assertTrue(TestUtils.grepTempOut("Adding the client certificate with sn EF34242D2324"));

        TestUtils.assertSuccessfulExecution(new String[]{"listauthorizedclients",
                    "TIMESTAMPSIGNER1000"});
        assertTrue(TestUtils.grepTempOut("ef34242d2324, CN=Test Root CA"));

        TestUtils.assertSuccessfulExecution(new String[]{"removeauthorizedclient",
                    "TIMESTAMPSIGNER1000",
                    "EF34242D2324",
                    "CN=Test Root CA"});
        assertTrue(TestUtils.grepTempOut("Client Removed"));

        TestUtils.assertSuccessfulExecution(new String[]{"listauthorizedclients",
                    "TIMESTAMPSIGNER1000"});
        assertFalse(TestUtils.grepTempOut("ef34242d2324, CN=Test Root CA"));


        // Dump
        TestUtils.assertSuccessfulExecution(new String[]{"dumpproperties",
                    "TIMESTAMPSIGNER1000",
                    getSignServerHome() + "/tmp/testdump.properties"});
        assertTrue(TestUtils.grepTempOut("Properties successfully dumped into file"));


        Properties props = new Properties();
        props.load(new FileInputStream(getSignServerHome() + "/tmp/testdump.properties"));
        assertNotNull(props.get("WORKER1000.AUTHTYPE"));

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
        } catch (ExitException e) {
            TestUtils.printTempErr();
            TestUtils.printTempOut();
            assertTrue(false);
        }

        TestingSecurityManager.remove();
    }

    public void testRemoveTimeStamp() throws Exception {
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
    
    /**
     * Test adding and removing WS admins using serial number and issuer DN directly
     * @throws Exception
     */
    public void testWSAdmins() throws Exception {
    	// Test adding wsadmin using explicit parameters
    	TestUtils.assertSuccessfulExecution(new String[] {"wsadmins", "-add",
    			"-certserialno", "EF34242D2324", "-issuerdn", "CN=Test Root CA"});
    	TestUtils.assertSuccessfulExecution(new String[] {"wsadmins", "-list"});
    	assertTrue(TestUtils.grepTempOut("EF34242D2324"));
    	assertTrue(TestUtils.grepTempOut("CN=Test Root CA"));
    	     
        // Test removing previously added admin
    	TestUtils.assertSuccessfulExecution(new String[] {"wsadmins", "-remove",
    			"-certserialno", "EF34242D2324", "-issuerdn", "CN=Test Root CA"});
    	TestUtils.assertSuccessfulExecution(new String[] {"wsadmins", "-list"});
    	assertFalse(TestUtils.grepTempOut("EF34242D2324"));
    	assertFalse(TestUtils.grepTempOut("CN=Test Root CA"));
 
    }
    
    /**
     * Test running the signdocument command using webservices with a PDF signer set up to archive
     * based on the request filename property
     * @throws Exception
     */
    public void testWSWithFileName() throws Exception {
    	// set up a test PDF signer using the file logger to log to a temporary file
    	File logFile = File.createTempFile("pdf-signer", ".log");
    	File outFile = File.createTempFile("dummy-output", ".pdf");
    	
    	// make sure temp files are deleted when the VM exits
    	logFile.deleteOnExit();
    	outFile.deleteOnExit();
    	
    	addPDFSigner1();
    	
    	TestUtils.assertSuccessfulExecution(new String[] {"setproperty", Integer.toString(getSignerIdPDFSigner1()),
    										"WORKERLOGGER", "org.signserver.server.log.FileWorkerLogger"});
    	TestUtils.assertSuccessfulExecution(new String[] {"setproperty", Integer.toString(getSignerIdPDFSigner1()),
    										"LOG_FILE_PATH", logFile.getAbsolutePath()});
    	TestUtils.assertSuccessfulExecution(new String[] {"reload", Integer.toString(getSignerIdPDFSigner1())});
    	
    	// execute test signing a PDF file with the client CLI in WS mode
    	// we run the client CLI commands by invoking main() directly, we are only interested in the output log file
    	// redirect the output PDF to a temporary file to avoid clubbering stdout when running the test
    	DocumentSignerCLI.main(new String[] {"-protocol", "WEBSERVICES", "-workername", getSignerNamePDFSigner1(), "-infile",
    			getSignServerHome() + File.separator + "src" + File.separator + "test" + File.separator + "pdf" + File.separator + "sample.pdf",
    			"-outfile", outFile.getAbsolutePath(), "-truststore",
    			getSignServerHome() + File.separator + "p12" + File.separator + "truststore.jks",
    			"-truststorepwd", "changeit"});
    	
    	// check the log file to see that the FILENAME property was logged
    	BufferedReader reader = new BufferedReader(new FileReader(logFile));
    	final String line = reader.readLine();
    	
    	reader.close();
    	
    	final String[] fields = line.split(";");
    	boolean found = false;
    	
    	for (final String field : fields) {
    		final String[] parts = field.split(":");
    		
    		if (parts.length != 2) {
    			continue;
    		}
    		
    		final String key = parts[0].trim();
    		if ("FILENAME".equals(key)) {
    			final String value = parts[1].trim();
    			// check if log value matches file name of original PDF file
    			
    			found = "sample.pdf".equals(value);
    		}
    	}
    	
    	removeWorker(getSignerIdPDFSigner1());
    	
    	assertTrue("FILENAME property is not logged", found);
    }
}
