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
import org.apache.commons.lang.StringUtils;
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
 * Class used to test the basic aspects of the SignServer CLI such
 * as get status, activate, set properties etc..
 * 
 * @author Philip Vendil 21 okt 2007
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SignServerCLITest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SignServerCLITest.class);
    
    private static final int WORKERID1 = 100;
    private static final String TESTID = String.valueOf(WORKERID1);
    private static final int WORKERID2 = 1000;
    private static final String TESTTSID = String.valueOf(WORKERID2);

    private CLITestHelper cli = getAdminCLI();
    private CLITestHelper clientCLI = getClientCLI();


    @Test
    public void test01BasicSetup() throws Exception {
        
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
        
        assertEquals("Setproperty 3", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", "" + TESTID, "FOO", "bar"));
        // test the getproperty CLI command for a worker property
        assertEquals("Getproperty 1", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("getproperty", "" + TESTID, "FOO"));
        assertPrinted("Contains property value", cli.getOut(), "bar");
        
        // test the getproperty CLI command for a non-existing worker property
        assertEquals("Getproperty 2", CommandLineInterface.RETURN_ERROR,
                cli.execute("getproperty", "" + TESTID, "bogus"));
        assertPrinted("Contains error message", cli.getOut(), "No such property");
    
        assertEquals("Setproperty 4", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", "global", "GLOBFOO", "bar"));
        // test the getproperty CLI command for a global property
        assertEquals("Getproperty 3", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("getproperty", "global", "GLOBFOO"));
        assertPrinted("Contains property", cli.getOut(), "bar");
        
        // test the getproperty CLI command for an unknown global property
        assertEquals("Getproperty 4", CommandLineInterface.RETURN_ERROR,
                cli.execute("getproperty", "global", "_UNKNOWN_"));
        assertPrinted("Contains property", cli.getOut(), "No such global property");
    }

    @Test
    public void test01SetupTimeStamp() throws Exception {

        assertTrue(new File(getSignServerHome() + "/res/test/test_add_timestamp_configuration.properties").exists());
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                cli.execute("setproperties", getSignServerHome() + "/res/test/test_add_timestamp_configuration.properties"));
        assertPrinted("", cli.getOut(), "Setting the property NAME to timestampSigner1000 for worker 1000");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", "1000", "KEYSTOREPATH",
                        getSignServerHome() + "/res/test/dss10/dss10_tssigner1.p12"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", "1000", "KEYSTORETYPE", "PKCS12"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", "1000", "KEYSTOREPASSWORD", "foo123"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("setproperty", "1000", "DEFAULTKEY", "TS Signer 1"));
        
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
                    "foo123"));
        assertPrinted("", cli.getOut(), "Activation of worker was successful");


        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("deactivatesigntoken", TESTTSID));
        assertPrinted("", cli.getOut(), "Deactivation of worker was successful");


        // Test operations by name
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("activatecryptotoken", "timestampSigner1000", "foo123"));
        assertPrinted("", cli.getOut(), "Activation of worker was successful");
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("activatecryptotoken", "TIMESTAMPSIGNER1000", "foo123"));
        assertFalse("", CommandLineInterface.RETURN_SUCCESS ==
            cli.execute("activatecryptotoken", "TIMESTAMPSIGNER2000", "foo123"));

        // Test authorized clients
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("addauthorizedclient", "TIMESTAMPSIGNER1000", "EF34242D2324", "CN=Test Root CA"));
        assertPrinted("", cli.getOut(), "Adding the client certificate with sn ef34242d2324");
        // test adding an authorized client via a PEM file
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        	cli.execute("addauthorizedclient", "TIMESTAMPSIGNER1000",
        			getSignServerHome() + "/res/test/dss10/dss10_signer1.pem"));
        System.out.println("Out: " + cli.getOut().toString());
        assertPrinted("", cli.getOut(),
        		"Adding the client certificate with sn 41935ada62ee0e8a and " +
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
        
        // test adding an authorized client specifying leading zero in SN
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("addauthorizedclient", "TIMESTAMPSIGNER1000", "0FF34242D2324", "CN=Test Root CA"));
        assertPrinted("", cli.getOut(), "Adding the client certificate with sn ff34242d2324");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("listauthorizedclients", "TIMESTAMPSIGNER1000"));
        assertPrinted("", cli.getOut(), "ff34242d2324, CN=Test Root CA");
        
        // test removing authorized client specifying SN with leading 0 and upper-case
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, cli.execute("removeauthorizedclient",
                    "TIMESTAMPSIGNER1000",
                    "0FF34242D2324",
                    "CN=Test Root CA"));
        assertPrinted("", cli.getOut(), "Client Removed");
        
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

    @Test
    public void test01RemoveTimeStamp() throws Exception {
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
    }

    /**
     * Test adding and removing WS admins using serial number and issuer DN directly.
     * @throws Exception
     */
    @Test
    public void test01WSAdmins() throws Exception {
    	// Test adding wsadmin using explicit parameters
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("wsadmins", "-add", "-certserialno", "ef34242d2324",
            		"-issuerdn", "CN=Test Root CA"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        	cli.execute("wsadmins", "-list"));
       
        assertPrinted("", cli.getOut(), "ef34242d2324");
        assertPrinted("", cli.getOut(), "CN=Test Root CA");
        
        // try adding the same admin again
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("wsadmins", "-add", "-certserialno", "ef34242d2324",
            		"-issuerdn", "CN=Test Root CA"));
        assertPrinted("", cli.getOut(), "Administrator already exists");
        
        // Test removing previously added admin
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-remove", "-certserialno", "ef34242d2324",
            		"-issuerdn", "CN=Test Root CA"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-list"));
        assertNotPrinted("", cli.getOut(), "ef34242d2324");
        assertNotPrinted("", cli.getOut(), "CN=Test Root CA");
        
        // Test adding wsadmin with leading zero in serial number
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("wsadmins", "-add", "-certserialno", "0df34242d2324",
            		"-issuerdn", "CN=Test Root CA"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        	cli.execute("wsadmins", "-list"));
       
        assertPrinted("", cli.getOut(), "df34242d2324");
        assertPrinted("", cli.getOut(), "CN=Test Root CA");
        
        // Test removing previously added admin
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-remove", "-certserialno", "0df34242d2324",
            		"-issuerdn", "CN=Test Root CA"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-list"));
        assertNotPrinted("", cli.getOut(), "df34242d2324");
        assertNotPrinted("", cli.getOut(), "CN=Test Root CA");

        // Test adding wsadmin with serial number given in with upper case
        // hex letters and test that the -list output is given in internal
        // (BigInteger.toString(16) ) form
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("wsadmins", "-add", "-certserialno", "FF34242D2324",
            		"-issuerdn", "CN=Test Root CA"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        	cli.execute("wsadmins", "-list"));
       
        assertPrinted("", cli.getOut(), "ff34242d2324");
        assertPrinted("", cli.getOut(), "CN=Test Root CA");

        // Test removing previously added admin
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-remove", "-certserialno", "FF34242D2324",
            		"-issuerdn", "CN=Test Root CA"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-list"));
        assertNotPrinted("", cli.getOut(), "ff34242d2324");
        assertNotPrinted("", cli.getOut(), "CN=Test Root CA");
        
        // Test setting any WS admin allowed
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("wsadmins", "-allowany"));
        assertPrinted("", cli.getOut(), "Set to allow any WS admin");
        
        // check that the list command shows a warning when allow any is on
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("wsadmins", "-list"));
        assertPrinted("", cli.getOut(), "ANY CERTIFICATE ACCEPTED FOR WS ADMINISTRATORS");
    
        // Test turning off allowing any WS admin
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("wsadmins", "-allowany", "false"));
        assertPrinted("", cli.getOut(), "Set to not allow any WS admin");
        
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("wsadmins", "-list"));
        assertNotPrinted("", cli.getOut(), "ANY CERTIFICATE ACCEPTED FOR WS ADMINISTRATORS");
        
        // Test with invalid hexadecimal serial number
        assertEquals("", CommandLineInterface.RETURN_INVALID_ARGUMENTS,
                cli.execute("wsadmins", "-add", "-certserialno", "foo",
                        "-issuerdn", "CN=foo"));
        assertPrinted("", cli.getOut(), "Illegal serial number specified: foo");
        assertEquals("", CommandLineInterface.RETURN_INVALID_ARGUMENTS,
                cli.execute("wsadmins", "-remove", "-certserialno", "foo",
                        "-issuerdn", "CN=foo"));
        assertPrinted("", cli.getOut(), "Illegal serial number specified: foo");
    }
    
    /**
     * Test adding WS admins using PEM and DER files.
     * @throws Exception
     */
    @Test
    public void test01WSAdminsFromFile() throws Exception {
    	// Test adding wsadmin using a PEM file
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-add",
        				"-cert", getSignServerHome() + "/res/test/dss10/dss10_signer1.pem"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-list"));
        assertPrinted("", cli.getOut(), "41935ada62ee0e8a");
        assertPrinted("", cli.getOut(), "C=SE, O=SignServer, OU=Testing, CN=DSS Root CA 10");
     
        // Test adding wsadmin using a DER file
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-add",
        				"-cert", getSignServerHome() + "/res/test/dss10/dss10_signer2.der"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsadmins", "-list"));
        assertPrinted("", cli.getOut(), "53f6992d081248a");
        assertPrinted("", cli.getOut(), "C=SE, O=SignServer, OU=Testing, CN=DSS Root CA 10");
    }
    
    /**
     * Test adding and removing WS auditors using serial number and issuer DN directly.
     * @throws Exception
     */
    @Test
    public void test01WSAuditors() throws Exception {
    	// Test adding wsadmin using explicit parameters
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("wsauditors", "-add", "-certserialno", "ef34343d2428",
            		"-issuerdn", "CN=Test Root CA 2"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        	cli.execute("wsauditors", "-list"));
        assertPrinted("", cli.getOut(), "ef34343d2428");
        assertPrinted("", cli.getOut(), "CN=Test Root CA 2");
        
        // Test adding the same client again
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("wsauditors", "-add", "-certserialno", "ef34343d2428",
            		"-issuerdn", "CN=Test Root CA 2"));
        assertPrinted("", cli.getOut(), "Rule already exists");
        
        // Test removing previously added admin
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsauditors", "-remove", "-certserialno", "ef34343d2428",
            		"-issuerdn", "CN=Test Root CA 2"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsauditors", "-list"));
        assertNotPrinted("", cli.getOut(), "ef34343d2428");
        assertNotPrinted("", cli.getOut(), "CN=Test Root CA 2");
        
        // Test adding wsadmin using with leading zero in serial number
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("wsauditors", "-add", "-certserialno", "0df34343d2428",
            		"-issuerdn", "CN=Test Root CA 2"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        	cli.execute("wsauditors", "-list"));
        assertPrinted("", cli.getOut(), "df34343d2428");
        assertPrinted("", cli.getOut(), "CN=Test Root CA 2");
        
        // Test removing previously added admin
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsauditors", "-remove", "-certserialno", "0df34343d2428",
            		"-issuerdn", "CN=Test Root CA 2"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsauditors", "-list"));
        assertNotPrinted("", cli.getOut(), "df34343d2428");
        assertNotPrinted("", cli.getOut(), "CN=Test Root CA 2");
        
        // Test adding wsadmin using with upper case letters in serial number
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("wsauditors", "-add", "-certserialno", "FF34343D2428",
            		"-issuerdn", "CN=Test Root CA 2"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        	cli.execute("wsauditors", "-list"));
        assertPrinted("", cli.getOut(), "ff34343d2428");
        assertPrinted("", cli.getOut(), "CN=Test Root CA 2");
        
        // Test removing previously added admin
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsauditors", "-remove", "-certserialno", "FF34343D2428",
            		"-issuerdn", "CN=Test Root CA 2"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsauditors", "-list"));
        assertNotPrinted("", cli.getOut(), "ff34343d2428");
        assertNotPrinted("", cli.getOut(), "CN=Test Root CA 2");
        
        // Test with invalid hexadecimal serial number
        assertEquals("", CommandLineInterface.RETURN_INVALID_ARGUMENTS,
                cli.execute("wsauditors", "-add", "-certserialno", "foo",
                        "-issuerdn", "CN=foo"));
        assertPrinted("", cli.getOut(), "Illegal serial number specified: foo");
        assertEquals("", CommandLineInterface.RETURN_INVALID_ARGUMENTS,
                cli.execute("wsauditors", "-remove", "-certserialno", "foo",
                        "-issuerdn", "CN=foo"));
        assertPrinted("", cli.getOut(), "Illegal serial number specified: foo");
    }
    
    /**
     * Test adding and removing WS archive auditors using serial number and issuer DN directly.
     * @throws Exception
     */
    @Test
    public void test01WSArchiveAuditors() throws Exception {
        // Test adding wsadmin using explicit parameters
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("wsarchiveauditors", "-add", "-certserialno", "ef34343d2428",
                        "-issuerdn", "CN=Test Root CA 2"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("wsarchiveauditors", "-list"));
        assertPrinted("", cli.getOut(), "ef34343d2428");
        assertPrinted("", cli.getOut(), "CN=Test Root CA 2");
        
        // Test adding the same client again
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("wsarchiveauditors", "-add", "-certserialno", "ef34343d2428",
                        "-issuerdn", "CN=Test Root CA 2"));
        assertPrinted("", cli.getOut(), "Rule already exists");
        
        // Test removing previously added admin
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                        cli.execute("wsarchiveauditors", "-remove", "-certserialno", "ef34343d2428",
                        "-issuerdn", "CN=Test Root CA 2"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                        cli.execute("wsarchiveauditors", "-list"));
        assertNotPrinted("", cli.getOut(), "ef34343d2428");
        assertNotPrinted("", cli.getOut(), "CN=Test Root CA 2");
        
        // Test adding wsadmin with leading zero in serial number
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("wsarchiveauditors", "-add", "-certserialno", "0df34343d2428",
                        "-issuerdn", "CN=Test Root CA 2"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("wsarchiveauditors", "-list"));
        assertPrinted("", cli.getOut(), "df34343d2428");
        assertPrinted("", cli.getOut(), "CN=Test Root CA 2");
        
        // Test removing previously added admin
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                        cli.execute("wsarchiveauditors", "-remove", "-certserialno", "0df34343d2428",
                        "-issuerdn", "CN=Test Root CA 2"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                        cli.execute("wsarchiveauditors", "-list"));
        assertNotPrinted("", cli.getOut(), "df34343d2428");
        assertNotPrinted("", cli.getOut(), "CN=Test Root CA 2");
        
        // Test adding wsadmin using upper case letters in serial number
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("wsarchiveauditors", "-add", "-certserialno", "FF34343D2428",
                        "-issuerdn", "CN=Test Root CA 2"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                cli.execute("wsarchiveauditors", "-list"));
        assertPrinted("", cli.getOut(), "ff34343d2428");
        assertPrinted("", cli.getOut(), "CN=Test Root CA 2");
        
        // Test removing previously added admin
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                        cli.execute("wsarchiveauditors", "-remove", "-certserialno", "FF34343D2428",
                        "-issuerdn", "CN=Test Root CA 2"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                        cli.execute("wsarchiveauditors", "-list"));
        assertNotPrinted("", cli.getOut(), "ff34343d2428");
        assertNotPrinted("", cli.getOut(), "CN=Test Root CA 2");
        
        // Test with invalid hexadecimal serial number
        assertEquals("", CommandLineInterface.RETURN_INVALID_ARGUMENTS,
                cli.execute("wsarchiveauditors", "-add", "-certserialno", "foo",
                        "-issuerdn", "CN=foo"));
        assertPrinted("", cli.getOut(), "Illegal serial number specified: foo");
        assertEquals("", CommandLineInterface.RETURN_INVALID_ARGUMENTS,
                cli.execute("wsarchiveauditors", "-remove", "-certserialno", "foo",
                        "-issuerdn", "CN=foo"));
        assertPrinted("", cli.getOut(), "Illegal serial number specified: foo");
    }
    
    /**
     * Test adding WS auditors using PEM and DER files.
     * @throws Exception
     */
    @Test
    public void test01WSAuditorsFromFile() throws Exception {
    	// Test adding wsadmin using a PEM file
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsauditors", "-add",
        				"-cert", getSignServerHome() + "/res/test/dss10/dss10_signer1.pem"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsauditors", "-list"));
        assertPrinted("", cli.getOut(), "41935ada62ee0e8a");
        assertPrinted("", cli.getOut(), "C=SE, O=SignServer, OU=Testing, CN=DSS Root CA 10");
     
        // Test adding wsadmin using a DER file
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsauditors", "-add",
        				"-cert", getSignServerHome() + "/res/test/dss10/dss10_signer2.der"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
        		cli.execute("wsauditors", "-list"));
        assertPrinted("", cli.getOut(), "53f6992d081248a");
        assertPrinted("", cli.getOut(), "C=SE, O=SignServer, OU=Testing, CN=DSS Root CA 10");
    }
    
    /**
     * Test adding WS auditors using PEM and DER files.
     * @throws Exception
     */
    @Test
    public void test01WSArchiveAuditorsFromFile() throws Exception {
        // Test adding wsadmin using a PEM file
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                        cli.execute("wsarchiveauditors", "-add",
                                        "-cert", getSignServerHome() + "/res/test/dss10/dss10_signer1.pem"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                        cli.execute("wsarchiveauditors", "-list"));
        assertPrinted("", cli.getOut(), "41935ada62ee0e8a");
        assertPrinted("", cli.getOut(), "C=SE, O=SignServer, OU=Testing, CN=DSS Root CA 10");
     
        // Test adding wsadmin using a DER file
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                        cli.execute("wsarchiveauditors", "-add",
                                        "-cert", getSignServerHome() + "/res/test/dss10/dss10_signer2.der"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS,
                        cli.execute("wsarchiveauditors", "-list"));
        assertPrinted("", cli.getOut(), "53f6992d081248a");
        assertPrinted("", cli.getOut(), "C=SE, O=SignServer, OU=Testing, CN=DSS Root CA 10");
    }
    
    /**
     * Test running the signdocument command using webservices with a PDF signer set up to archive
     * based on the request filename property
     * @throws Exception
     */
    public void test01WSWithFileName() throws Exception {
    	// set up a test PDF signer using the file logger to log to a temporary file
    	File logFile = File.createTempFile("pdf-signer", ".log");
    	File outFile = File.createTempFile("dummy-output", ".pdf");
    	
    	// make sure temp files are deleted when the VM exits
    	logFile.deleteOnExit();
    	outFile.deleteOnExit();
    	
    	addPDFSigner1();
    	cli.execute("setproperty", Integer.toString(getSignerIdPDFSigner1()), "WORKERLOGGER", "org.signserver.server.log.FileWorkerLogger");
    	cli.execute("setproperty", Integer.toString(getSignerIdPDFSigner1()), "LOG_FILE_PATH", logFile.getAbsolutePath());
    	cli.execute("reload", Integer.toString(getSignerIdPDFSigner1()));
    	
    	// execute test signing a PDF file with the client CLI in WS mode
    	clientCLI.execute("signdocument", "-protocol", "WEBSERVICES", "-workername", getSignerNamePDFSigner1(), "-infile",
    			getSignServerHome() + File.separator + "res" + File.separator + "test" + File.separator + "pdf" + File.separator + "sample.pdf",
    			"-outfile", outFile.getAbsolutePath(),
                        "-truststore", getSignServerHome() + "/p12/truststore.jks", "-truststorepwd", "changeit",
                        "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort()));
   	
    	final String line;
        try ( // check the log file to see that the FILENAME property was logged
                BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            line = reader.readLine();
        }
    	
    	final String[] fields = line.split(";");
    	boolean found = false;
    	
    	for (final String field : fields) {
    		final String[] parts = field.split(":");
    		
    		if (parts.length != 2) {
    			continue;
    		}
    		
    		final String key = StringUtils.trim(parts[0]);
    		if ("FILENAME".equals(key)) {
    			final String value = StringUtils.trim(parts[1]);
    			// check if log value matches file name of original PDF file
    			
    			found = "sample.pdf".equals(value);
    		}
    	}
    	
    	removeWorker(getSignerIdPDFSigner1());
    	
    	assertTrue("FILENAME property is not logged", found);
    }
    
    @Test
    public void test99TearDownDatabase() throws Exception {
        LOG.info(">test99TearDownDatabase");
        removeWorker(WORKERID1);
        removeWorker(WORKERID2);
    }
}
