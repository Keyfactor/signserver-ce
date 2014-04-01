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
import java.security.Security;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TimeStampResponse;
import org.junit.Before;
import org.junit.Test;
import org.signserver.cli.CommandLineInterface;
import org.signserver.common.SignServerUtil;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;

/**
 * Tests for the timestamp command of Client CLI.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TimeStampCommandTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeStampCommandTest.class);

    private static final int WORKER1 = 8911;

    private final CLITestHelper cli = getClientCLI();
    
    private static final String SAMPLE_QUERY_FILE = "res/test/sample.tsq";
    private static final String SAMPLE_QUERY_CERTREQ_FILE = "res/test/sample-certreq.tsq";
    private static final String SAMPLE_RESPONSE_FILE = "res/test/sample.tsr";
    private static final String SAMPLE_RESPONSE_CERTREQ_FILE = "res/test/sample-certreq.tsr";
	
    @Before
    @Override
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }
	
    @Test
    public void test00SetupDatabase() throws Exception {
        setProperties(getClass().getResourceAsStream("ts-cli-configuration1.properties"));
        workerSession.reloadConfiguration(WORKER1);
    }

    @Test
    public void test01missingArguments() throws Exception {
        assertEquals("No arguments", CommandLineInterface.RETURN_INVALID_ARGUMENTS, 
                cli.execute("timestamp"));
    }

    /**
     * Tests getting a timestamp.
     * @throws Exception
     */
    @Test
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
     * @throws Exception
     */
    @Test
    public void test02requestATimestampOverHTTPS() throws Exception {
        File responseFile = File.createTempFile("signserver-" + this.getClass().getName() + "-response2-", null);
        responseFile.deleteOnExit();
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-instr", "Any text we want to have a timestamp for...123", "-outrep", responseFile.getAbsolutePath(), 
                "-url", "https://" + getHTTPHost() + ":" + getPublicHTTPSPort() + "/signserver/tsa?workerId=" + WORKER1, 
                "-truststore", getTestUtils().getTruststoreFile().getAbsolutePath(), "-truststorepwd", getTestUtils().getTrustStorePassword()));
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
     * Tests the CLI without having the BC provider installed as the CLI 
     * should install it itself.
     * @throws Exception 
     */
    @Test
    public void test03withoutBCalreadyInstalled() throws Exception {
        Security.removeProvider("BC");
        test02requestATimestamp();
    }
    
    /**
     * Tests printing requests.
     * @throws Exception
     */
    @Test
    public void test04printRequest() throws Exception {
        LOG.info("test04printRequest");
        final File requestFile = new File(getSignServerHome(), SAMPLE_QUERY_FILE);
        final File requestCertFile = new File(getSignServerHome(), SAMPLE_QUERY_CERTREQ_FILE);
        
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-print", "-inreq", requestFile.getAbsolutePath()));   
        String out = new String(cli.getOut().toByteArray());
        assertTrue("No request in: " + out, out.contains("Time-stamp request") && out.contains("}"));
        
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-print", "-inreq", requestCertFile.getAbsolutePath()));   
        out = new String(cli.getOut().toByteArray());
        assertTrue("No request in: " + out, out.contains("Time-stamp request") && out.contains("}"));
    }
    
    /**
     * Tests printing responses.
     * @throws Exception
     */
    @Test
    public void test05printResponses() throws Exception {
        LOG.info("test05printResponses");
        final File requestFile = new File(getSignServerHome(), SAMPLE_RESPONSE_FILE);
        final File requestCertFile = new File(getSignServerHome(), SAMPLE_RESPONSE_CERTREQ_FILE);
        
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-print", "-inrep", requestFile.getAbsolutePath()));   
        String out = new String(cli.getOut().toByteArray());
        assertTrue("No response in: " + out, out.contains("Time-stamp response") && out.contains("}"));
        
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-print", "-inrep", requestCertFile.getAbsolutePath()));   
        out = new String(cli.getOut().toByteArray());
        assertTrue("No response in: " + out, out.contains("Time-stamp response") && out.contains("}"));
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKER1);
    }
}
