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

import org.bouncycastle.tsp.TimeStampResponse;
import org.signserver.client.TimeStampClient;
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
    private static final String TESTGSID = "1023";

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

        assertTrue(new File(getSignServerHome() + "/res/test/test_add_timestamp_configuration.properties").exists());
        TestUtils.assertSuccessfulExecution(new String[]{"setproperties",
                    getSignServerHome() + "/res/test/test_add_timestamp_configuration.properties"});
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
        // Remove and restore
        TestUtils.assertSuccessfulExecution(new String[]{"setproperties",
                    getSignServerHome() + "/res/test/test_rem_timestamp_configuration.properties"});
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

    public void testSetupGroupKeyService() throws Exception {
        TestUtils.assertSuccessfulExecution(new String[]{"reload",
                    "all"});

        assertTrue(new File(getSignServerHome() + "/res/test/test_add_groupkeyservice_configuration.properties").exists());
        TestUtils.assertSuccessfulExecution(new String[]{"setproperties",
                    getSignServerHome() + "/res/test/test_add_groupkeyservice_configuration.properties"});
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
