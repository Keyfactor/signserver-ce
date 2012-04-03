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
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;
import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TimeStampResponse;
import org.signserver.client.cli.defaultimpl.TimeStampCommand;
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
    private static final String TESTGSID = "1023";

    private CLITestHelper cli = getAdminCLI();
    
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

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, cli.execute("archive",
                    "findfromarchiveid",
                    TESTTSID,
                    archiveId,
                    getSignServerHome() + "/tmp"));
        File datafile = new File(getSignServerHome() + "/tmp/" + archiveId);
        assertTrue(datafile.exists());
        datafile.delete();
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, cli.execute("archive",
                    "findfromrequestip",
                    TESTTSID,
                    "127.0.0.1",
                    getSignServerHome() + "/tmp"));
        datafile = new File(getSignServerHome() + "/tmp/" + archiveId);
        assertTrue(datafile.exists());
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

    public void testSetupGroupKeyService() throws Exception {
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

    public void testRemoveGroupKeyService() throws Exception {
        // Remove and restore
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("removeworker", "Test1"));
        assertPrinted("", cli.getOut(), "Property 'NAME' removed");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            cli.execute("reload", TESTGSID));
        assertPrinted("", cli.getOut(), "SignServer reloaded successfully");
    }


}
