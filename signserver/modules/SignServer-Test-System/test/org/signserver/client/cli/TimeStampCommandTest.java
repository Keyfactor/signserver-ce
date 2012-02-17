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
package org.signserver.client.cli;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TimeStampResponse;
import org.signserver.cli.CommandLineInterface;
import org.signserver.common.SignServerUtil;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests for the timestamp command of Client CLI.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TimeStampCommandTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeStampCommandTest.class);

    private static final int WORKER1 = 8911;

    private CLITestHelper cli = getClientCLI();
    
	
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }	
	
    public void test00SetupDatabase() throws Exception {
        setProperties(getClass().getResourceAsStream("ts-cli-configuration1.properties"));
        workerSession.reloadConfiguration(WORKER1);
    }

    public void test01missingArguments() throws Exception {
        assertEquals("No arguments", CommandLineInterface.RETURN_INVALID_ARGUMENTS, 
                cli.execute("timestamp"));
    }

    /**
     * Tests getting a timestamp.
     */
    public void test02requestATimestamp() throws Exception {
        File responseFile = File.createTempFile("signserver-" + this.getClass().getName() + "-response1-", null);
        responseFile.deleteOnExit();
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-instr", "Any text we want to have a timestamp for...123", "-outrep", responseFile.getAbsolutePath(), "-url", "http://localhost:8080/signserver/tsa?workerId=" + WORKER1));
        InputStream in = null;
        try {
            in = new FileInputStream(responseFile);
            TimeStampResponse res = new TimeStampResponse(in);
            assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }

    /**
     * Tests getting a timestamp over HTTPS (port 8442).
     */
    public void test02requestATimestampOverHTTPS() throws Exception {
        File responseFile = File.createTempFile("signserver-" + this.getClass().getName() + "-response2-", null);
        responseFile.deleteOnExit();
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-instr", "Any text we want to have a timestamp for...123", "-outrep", responseFile.getAbsolutePath(), "-url", "https://localhost:8442/signserver/tsa?workerId=" + WORKER1, "-truststore", getTestUtils().getTruststoreFile().getAbsolutePath(), "-truststorepwd", getTestUtils().getTrustStorePassword()));
        InputStream in = null;
        try {
            in = new FileInputStream(responseFile);
            TimeStampResponse res = new TimeStampResponse(in);
            assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }

    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKER1);
    }
}
