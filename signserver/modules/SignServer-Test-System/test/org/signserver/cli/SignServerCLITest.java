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

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TimeStampResponse;
import org.signserver.admin.cli.AdminCLI;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.client.cli.defaultimpl.TimeStampCommand;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TeeOutputStream;

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

    private ByteArrayOutputStream bout;
    private ByteArrayOutputStream berr;
    
    private int execute(String... args) throws UnexpectedCommandFailureException, IOException {
        bout = new ByteArrayOutputStream();
        berr = new ByteArrayOutputStream();
        AdminCLI cli = new AdminCLI();
        cli.setOut(new PrintStream(new TeeOutputStream(System.out, bout)));
        cli.setErr(new PrintStream(new TeeOutputStream(System.err, berr)));
        return cli.execute(args);
    }
    
    /**
     * A simple grep utility that searches a byte stream if the substring exists.
     * @param stream the output stream to grep in
     * @param searchString the text to search for.
     * @return true if searchString exists
     */
    private static boolean grep(ByteArrayOutputStream stream, String searchString) {
        Pattern p = Pattern.compile(searchString);
        // Create a matcher with an input string
        Matcher m = p.matcher(stream.toString());
        return m.find();
    }
    
    public static void assertPrinted(String message, ByteArrayOutputStream stream, String searchString) {
        assertTrue(message + ", expected: " + searchString, grep(stream, searchString));
    }
    
    public static void assertNotPrinted(String message, ByteArrayOutputStream stream, String searchString) {
        assertFalse(message + ", should not match: " + searchString, grep(stream, searchString));
    }
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    public void testBasicSetup() throws Exception {
        
        assertEquals("No arguments", CommandLineInterface.RETURN_INVALID_ARGUMENTS, 
                execute("noarguments"));
        assertPrinted("Print usages", bout, "use one of:");

        assertEquals("Setproperty", CommandLineInterface.RETURN_SUCCESS, 
                execute("setproperty", "global", "WORKER" + TESTID + ".CLASSPATH", "org.signserver.server.signers.TimeStampSigner"));

        assertEquals("Getconfig", CommandLineInterface.RETURN_SUCCESS, 
                execute("getconfig", "global"));
        assertPrinted("Prints a worker property", bout, "WORKER" + TESTID + ".CLASSPATH");

        assertEquals("Setproperty2", CommandLineInterface.RETURN_SUCCESS, 
                execute("setproperty", TESTID, "TESTKEY", "TESTVALUE"));

        assertEquals("Getconfig2", CommandLineInterface.RETURN_SUCCESS, 
                execute("getconfig", TESTID));
        assertPrinted("Contains TESTKEY",  bout, "TESTKEY");

        assertEquals("Removeproperty", CommandLineInterface.RETURN_SUCCESS, 
                execute("removeproperty", "" + TESTID, "TESTKEY"));
        assertEquals("Removeproperty2", CommandLineInterface.RETURN_SUCCESS, 
                execute("removeproperty", "global", "WORKER" + TESTID + ".CLASSPATH"));

        assertEquals("Getglobalconfig", CommandLineInterface.RETURN_SUCCESS, 
                execute("getconfig", "global"));
        assertNotPrinted("Contains a worker property", bout, "WORKER" + TESTID + ".CLASSPATH");

        assertEquals("Getconfig 3", CommandLineInterface.RETURN_SUCCESS, 
                execute("getconfig", "" + TESTID));
        assertNotPrinted("Contains TESTKEY", bout, "TESTKEY");

        assertEquals("Getconfig 4", CommandLineInterface.RETURN_SUCCESS, 
                execute("getconfig", "" + TESTID));
    }

    public void testSetupTimeStamp() throws Exception {

        assertTrue(new File(getSignServerHome() + "/res/test/test_add_timestamp_configuration.properties").exists());
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                execute("setproperties", getSignServerHome() + "/res/test/test_add_timestamp_configuration.properties"));
        assertPrinted("", bout, "Setting the property NAME to timestampSigner1000 for worker 1000");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                execute("reload", "1000"));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                execute("getstatus", "complete", TESTTSID));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                execute("setproperty", TESTTSID, "TESTKEY", "TESTVALUE"));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                execute("getstatus", "complete", TESTTSID));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                execute("reload", TESTTSID));
        assertPrinted("", bout, "SignServer reloaded successfully");


        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                execute("getstatus", "complete", TESTTSID));
        assertPrinted("", bout, "NAME=timestampSigner1000");
        assertPrinted("", bout, "TESTKEY");


        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                execute("reload", TESTTSID));
        assertPrinted("", bout, "SignServer reloaded successfully");


        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                execute("getstatus", "complete", TESTTSID));
        assertPrinted("", bout, "NAME=timestampSigner1000");

        // Test token operations
        assertFalse("", CommandLineInterface.RETURN_SUCCESS ==
                execute("activatesigntoken", TESTTSID, "9876"));
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, execute("activatesigntoken",
                    TESTTSID,
                    "1234"));
        assertPrinted("", bout, "Activation of worker was successful");


        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("deactivatesigntoken", TESTTSID));
        assertPrinted("", bout, "Deactivation of worker was successful");


        // Test operations by name
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("activatecryptotoken", "timestampSigner1000", "1234"));
        assertPrinted("", bout, "Activation of worker was successful");
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("activatecryptotoken", "TIMESTAMPSIGNER1000", "1234"));
        assertFalse("", CommandLineInterface.RETURN_SUCCESS ==
            execute("activatecryptotoken", "TIMESTAMPSIGNER2000", "1234"));

        // Test authorized clients
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("addauthorizedclient", "TIMESTAMPSIGNER1000", "EF34242D2324", "CN=Test Root CA"));
        assertPrinted("", bout, "Adding the client certificate with sn EF34242D2324");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("listauthorizedclients", "TIMESTAMPSIGNER1000"));
        assertPrinted("", bout, "ef34242d2324, CN=Test Root CA");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, execute("removeauthorizedclient",
                    "TIMESTAMPSIGNER1000",
                    "EF34242D2324",
                    "CN=Test Root CA"));
        assertPrinted("", bout, "Client Removed");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, execute("listauthorizedclients",
                    "TIMESTAMPSIGNER1000"));
        assertNotPrinted("", bout, "ef34242d2324, CN=Test Root CA");


        // Dump
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, execute("dumpproperties",
                    "TIMESTAMPSIGNER1000",
                    getSignServerHome() + "/tmp/testdump.properties"));
        assertPrinted("", bout, "Properties successfully dumped into file");


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

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, execute("archive",
                    "findfromarchiveid",
                    TESTTSID,
                    archiveId,
                    getSignServerHome() + "/tmp"));
        File datafile = new File(getSignServerHome() + "/tmp/" + archiveId);
        assertTrue(datafile.exists());
        datafile.delete();
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, execute("archive",
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
                execute("setproperties", getSignServerHome() + "/res/test/test_rem_timestamp_configuration.properties"));
        assertPrinted("", bout, "Removing the property NAME  for worker 1000");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                execute("getconfig", TESTTSID));
        assertNotPrinted("", bout, "NAME=timestampSigner1000");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                execute("removeproperty", TESTTSID, "TESTKEY"));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
                execute("reload", TESTTSID));
        assertPrinted("", bout, "SignServer reloaded successfully");
    }

    public void testSetupGroupKeyService() throws Exception {
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("reload", "all"));

        assertTrue(new File(getSignServerHome() + "/res/test/test_add_groupkeyservice_configuration.properties").exists());
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("setproperties", getSignServerHome() + "/res/test/test_add_groupkeyservice_configuration.properties"));
        assertPrinted("", bout, "Setting the property NAME to Test1 for worker 1023");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("reload", TESTGSID));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("getstatus", "complete", TESTGSID));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("groupkeyservice", "switchenckey", "" + TESTGSID));
        assertPrinted("", bout, "key switched successfully");
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("groupkeyservice", "switchenckey", "Test1"));
        assertPrinted("", bout, "key switched successfully");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("groupkeyservice", "pregeneratekeys", "" + TESTGSID, "1"));
        assertPrinted("", bout, "1 Pregenerated successfully");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("groupkeyservice", "pregeneratekeys", "" + TESTGSID, "101"));
        assertPrinted("", bout, "101 Pregenerated successfully");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("groupkeyservice", "pregeneratekeys", "" + TESTGSID, "1000"));
        assertPrinted("", bout, "1000 Pregenerated successfully");

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        String startDate = dateFormat.format(new Date(0));
        String endDate = dateFormat.format(new Date(System.currentTimeMillis() + 120000));

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("groupkeyservice", "removegroupkeys", "" + TESTGSID, "created", startDate, endDate));
        assertPrinted("", bout, "1102 Group keys removed");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("groupkeyservice", "removegroupkeys", "" + TESTGSID, "FIRSTUSED", startDate, endDate));
        assertPrinted("", bout, "0 Group keys removed");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("groupkeyservice", "removegroupkeys", "" + TESTGSID, "LASTFETCHED", startDate, endDate));
        assertPrinted("", bout, "0 Group keys removed");
    }

    public void testRemoveGroupKeyService() throws Exception {
        // Remove and restore
        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("removeworker", "Test1"));
        assertPrinted("", bout, "Property 'NAME' removed");

        assertEquals("", CommandLineInterface.RETURN_SUCCESS, 
            execute("reload", TESTGSID));
        assertPrinted("", bout, "SignServer reloaded successfully");
    }


}
