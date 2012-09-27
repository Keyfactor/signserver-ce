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
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TimeStampResponse;
import org.signserver.client.cli.defaultimpl.TimeStampCommand;
import org.signserver.module.pdfsigner.PDFSigner;
import org.signserver.testutils.CLITestHelper;
import static org.signserver.testutils.CLITestHelper.assertNotPrinted;
import static org.signserver.testutils.CLITestHelper.assertPrinted;
import org.signserver.testutils.ModulesTestCase;

/**
 * Class used to test the basic aspects of the SignServer CLI such
 * as get status, activate, set properties etc..
 * 
 * @author Philip Vendil 21 okt 2007
 * @version $Id$
 */
public class SignServerCLITest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignServerCLITest.class);
    
    private static final String TESTID = "100";
    private static final String TESTTSID = "1000";

    private CLITestHelper cli = getAdminCLI();
    private CLITestHelper clientCLI = getClientCLI();
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    public void testBasicSetup() throws Exception {
        
        assertEquals("No arguments", CommandLineInterface.RETURN_INVALID_ARGUMENTS, 
                cli.execute("noarguments"));
        assertPrinted("Print usages", cli.getOut(), "use one of:");

        assertEquals("Setproperty", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("setproperty", "global", "WORKER" + TESTID + ".CLASSPATH", "org.signserver.server.signers.TimeStampSigner"));

        assertEquals("Getconfig", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("getconfig", "global"));
        assertPrinted("Prints a worker property", cli.getOut(), "WORKER" + TESTID + ".CLASSPATH");

        assertEquals("Setproperty2", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("setproperty", TESTID, "TESTKEY", "TESTVALUE"));

        assertEquals("Getconfig2", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("getconfig", TESTID));
        assertPrinted("Contains TESTKEY",  cli.getOut(), "TESTKEY");

        assertEquals("Removeproperty", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("removeproperty", "" + TESTID, "TESTKEY"));
        assertEquals("Removeproperty2", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("removeproperty", "global", "WORKER" + TESTID + ".CLASSPATH"));

        assertEquals("Getglobalconfig", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("getconfig", "global"));
        assertNotPrinted("Contains a worker property", cli.getOut(), "WORKER" + TESTID + ".CLASSPATH");

        assertEquals("Getconfig 3", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("getconfig", "" + TESTID));
        assertNotPrinted("Contains TESTKEY", cli.getOut(), "TESTKEY");

        assertEquals("Getconfig 4", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("getconfig", "" + TESTID));
    }

    public void testSetupTimeStamp() throws Exception {

        assertTrue(new File(getSignServerHome() + "/res/test/test_add_timestamp_configuration.properties").exists());
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("setproperties", getSignServerHome() + "/res/test/test_add_timestamp_configuration.properties"));
        assertPrinted("", cli.getOut(), "Setting the property NAME to timestampSigner1000 for worker 1000");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("reload", "1000"));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("getstatus", "complete", TESTTSID));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("setproperty", TESTTSID, "TESTKEY", "TESTVALUE"));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("getstatus", "complete", TESTTSID));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("reload", TESTTSID));
        assertPrinted("", cli.getOut(), "SignServer reloaded successfully");


        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("getstatus", "complete", TESTTSID));
        assertPrinted("", cli.getOut(), "NAME=timestampSigner1000");
        assertPrinted("", cli.getOut(), "TESTKEY");


        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("reload", TESTTSID));
        assertPrinted("", cli.getOut(), "SignServer reloaded successfully");


        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("getstatus", "complete", TESTTSID));
        assertPrinted("", cli.getOut(), "NAME=timestampSigner1000");

        // Test token operations
        assertFalse("", CommandLineInterface.RETURN_SUCCESS ==
                cli.execute("activatesigntoken", TESTTSID, "9876"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, cli.execute("activatesigntoken",
                    TESTTSID,
                    "1234"));
        assertPrinted("", cli.getOut(), "Activation of worker was successful");


        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("deactivatesigntoken", TESTTSID));
        assertPrinted("", cli.getOut(), "Deactivation of worker was successful");


        // Test operations by name
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("activatecryptotoken", "timestampSigner1000", "1234"));
        assertPrinted("", cli.getOut(), "Activation of worker was successful");
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("activatecryptotoken", "TIMESTAMPSIGNER1000", "1234"));
        assertFalse("", CommandLineInterface.RETURN_SUCCESS ==
            cli.execute("activatecryptotoken", "TIMESTAMPSIGNER2000", "1234"));

        // Test authorized clients
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("addauthorizedclient", "TIMESTAMPSIGNER1000", "EF34242D2324", "CN=Test Root CA"));
        assertPrinted("", cli.getOut(), "Adding the client certificate with sn EF34242D2324");
        // test adding an authorized client via a PEM file
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        	cli.execute("addauthorizedclient", "TIMESTAMPSIGNER1000",
        			getSignServerHome() + "/res/test/dss10/dss10_signer1.pem"));
        assertPrinted("", cli.getOut(),
        		"Adding the client certificate with sn 1d9fa8b71c75b564 and " +
        	    "issuerDN : CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE");
        // test adding an authorized client via a DER file
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
            	cli.execute("addauthorizedclient", "TIMESTAMPSIGNER1000",
            			getSignServerHome() + "/res/test/dss10/dss10_signer2.der"));
        assertPrinted("", cli.getOut(),
            		"Adding the client certificate with sn 53f6992d081248a and " +
            	    "issuerDN : CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE");
        
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("listauthorizedclients", "TIMESTAMPSIGNER1000"));
        assertPrinted("", cli.getOut(), "ef34242d2324, CN=Test Root CA");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, cli.execute("removeauthorizedclient",
                    "TIMESTAMPSIGNER1000",
                    "EF34242D2324",
                    "CN=Test Root CA"));
        assertPrinted("", cli.getOut(), "Client Removed");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, cli.execute("listauthorizedclients",
                    "TIMESTAMPSIGNER1000"));
        assertNotPrinted("", cli.getOut(), "ef34242d2324, CN=Test Root CA");


        // Dump
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, cli.execute("dumpproperties",
                    "TIMESTAMPSIGNER1000",
                    getSignServerHome() + "/tmp/testdump.properties"));
        assertPrinted("", cli.getOut(), "Properties successfully dumped into file");


        Properties props = new Properties();
        props.load(new FileInputStream(getSignServerHome() + "/tmp/testdump.properties"));
        assertNotNull(props.get("WORKER1000.AUTHTYPE"));

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
    }

    public void testRemoveTimeStamp() throws Exception {
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

    /**
     * Test adding and removing WS admins using serial number and issuer DN directly
     * @throws Exception
     */
    public void testWSAdmins() throws Exception {
    	// Test adding wsadmin using explicit parameters
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("wsadmins", "-add", "-certserialno", "EF34242D2324",
            		"-issuerdn", "CN=Test Root CA"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        	cli.execute("wsadmins", "-list"));
        assertPrinted("", cli.getOut(), "EF34242D2324");
        assertPrinted("", cli.getOut(), "CN=Test Root CA");
        
        // Test removing previously added admin
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-remove", "-certserialno", "EF34242D2324",
            		"-issuerdn", "CN=Test Root CA"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-list"));
        assertNotPrinted("", cli.getOut(), "EF34242D2324");
        assertNotPrinted("", cli.getOut(), "CN=Test Root CA");
     
        
    }
    
    /**
     * Test adding WS admins using PEM and DER files
     * @throws Exception
     */
    public void testWSAdminsFromFile() throws Exception {
    	// Test adding wsadmin using a PEM file
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-add",
        				"-cert", getSignServerHome() + "/res/test/dss10/dss10_signer1.pem"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-list"));
        assertPrinted("", cli.getOut(), "1d9fa8b71c75b564");
        assertPrinted("", cli.getOut(), "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE");
     
        // Test adding wsadmin using a DER file
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-add",
        				"-cert", getSignServerHome() + "/res/test/dss10/dss10_signer2.der"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-list"));
        assertPrinted("", cli.getOut(), "53f6992d081248a");
        assertPrinted("", cli.getOut(), "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE");
    }
    
    /**
     * Test running the signdocument command using webservices with a PDF signer set up to archive
     * based on the request filename property
     * @throws Exception
     */
    public void testWSWithFileName() throws Exception {
    	// we use the PDFSigner's archive to disk functionallity to verify that the filename property
    	// is handled properly when signing through the WS interface (this way we don't have to implement
    	// some custom logger)
    	
    	File logFile = File.createTempFile("pdf-signer", ".log");
    	File outFile = File.createTempFile("dummy-output", ".pdf");
    	
    	// make sure temp files are deleted when the test exits
    	logFile.deleteOnExit();
    	outFile.deleteOnExit();
    	
    	addPDFSigner1();
    	cli.execute("setproperty", Integer.toString(getSignerIdPDFSigner1()), "WORKERLOGGER", "org.signserver.server.log.FileWorkerLogger");
    	cli.execute("setproperty", Integer.toString(getSignerIdPDFSigner1()), "LOG_FILE_PATH", logFile.getAbsolutePath());
    	cli.execute("reload", Integer.toString(getSignerIdPDFSigner1()));
    	
    	// execute test signing a PDF file with the client CLI in WS mode
    	clientCLI.execute("signdocument", "-protocol", "WEBSERVICES", "-workername", getSignerNamePDFSigner1(), "-infile",
    			getSignServerHome() + File.separator + "res" + File.separator + "test" + File.separator + "pdf" + File.separator + "sample.pdf",
    			"-outfile", outFile.getAbsolutePath());
    	
    	// delete temporary output file
    	outFile.delete();
    	
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
