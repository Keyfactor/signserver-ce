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
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.ejb.interfaces.WorkerSession;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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

    private final CLITestHelper cli = getClientCLI();

    private static final String SAMPLE_QUERY_FILE = "res/test/sample.tsq";
    private static final String SAMPLE_QUERY_CERTREQ_FILE = "res/test/sample-certreq.tsq";
    private static final String SAMPLE_RESPONSE_FILE = "res/test/sample.tsr";
    private static final String SAMPLE_RESPONSE_CERTREQ_FILE = "res/test/sample-certreq.tsr";

    private final WorkerSession workerSession = getWorkerSession();

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        addTimeStampSigner(getSignerIdTimeStampSigner1(), getSignerNameTimeStampSigner1(), true);
        workerSession.setWorkerProperty(getSignerIdTimeStampSigner1(), "DEFAULTTSAPOLICYOID", "1.2.13.1");
        workerSession.removeWorkerProperty(getSignerIdTimeStampSigner1(), "ACCEPTANYPOLICY");
        workerSession.setWorkerProperty(getSignerIdTimeStampSigner1(), "ACCEPTEDPOLICIES", "1.2.13.1;1.2.13.9");
        workerSession.reloadConfiguration(getSignerIdTimeStampSigner1());
    }

    @Test
    public void test01missingArguments() throws Exception {
        assertEquals("No arguments", CommandLineInterface.RETURN_INVALID_ARGUMENTS,
                cli.execute("timestamp"));
    }

    /**
     * Tests getting a timestamp.
     */
    @Test
    public void test02requestATimestamp() throws Exception {
        File responseFile = File.createTempFile("signserver-" + this.getClass().getName() + "-response1-", null);
        responseFile.deleteOnExit();
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-instr", "Any text we want to have a timestamp for...123", "-outrep", responseFile.getAbsolutePath(), "-url", "http://localhost:8080/signserver/tsa?workerId=" + getSignerIdTimeStampSigner1()));
        try (InputStream in = new FileInputStream(responseFile)) {
            TimeStampResponse res = new TimeStampResponse(in);
            assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
        }
    }

    /**
     * Tests getting a timestamp over HTTPS (port 8442).
     */
    @Test
    public void test02requestATimestampOverHTTPS() throws Exception {
        File responseFile = File.createTempFile("signserver-" + this.getClass().getName() + "-response2-", null);
        responseFile.deleteOnExit();
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-instr", "Any text we want to have a timestamp for...123", "-outrep", responseFile.getAbsolutePath(),
                "-url", "https://" + getHTTPHost() + ":" + getPublicHTTPSPort() + "/signserver/tsa?workerId=" + getSignerIdTimeStampSigner1(),
                "-truststore", getTestUtils().getTruststoreFile().getAbsolutePath(), "-truststorepwd", getTestUtils().getTrustStorePassword()));
        try (InputStream in = new FileInputStream(responseFile)) {
            TimeStampResponse res = new TimeStampResponse(in);
            assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
        }
    }

    /**
     * Tests the CLI without having the BC provider installed as the CLI
     * should install it itself.
     */
    @Test
    public void test03withoutBCalreadyInstalled() throws Exception {
        Security.removeProvider("BC");
        test02requestATimestamp();
    }

    /**
     * Tests printing requests.
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

    /**
     * Test that trying to use a URL pointing to a non-existing worker will
     * print out the HTTP error code and message on the error stream.
     */
    @Test
    public void test06unknownWorker() throws Exception {
        assertEquals(CommandLineInterface.RETURN_ERROR,
                cli.execute("timestamp", "-instr",
                            "Any text we want to have a timestamp for...123",
                            "-url", "http://localhost:8080/signserver/tsa?workerName=_nonExisting"));
        final String err = new String(cli.getErr().toByteArray());
        // JBoss seems to rewrite HTTP error message, so check both variants
        assertTrue("Prints HTTP error 404: " + err,
                err.contains("Failure: HTTP error: 404: Not Found") ||
                err.contains("Failure: HTTP error: 404: Worker Not Found"));
    }

    /**
     * Tests that command fails when invalid digest algorithm is provided.
     */
    @Test
    public void test07InvalidDigestAlgorithm() throws Exception {
        try {
            cli.execute("timestamp", "-instr",
                    "Any text we want to have a timestamp for...123",
                    "-url", "http://localhost:8080/signserver/tsa?workerId=" + getSignerIdTimeStampSigner1(), "-digestalgorithm", "invalidDigestAlgorithm");
            fail("should fail");
        } catch (UnexpectedCommandFailureException e) {
            assertTrue("Should throw exception: " + e.getMessage(), e.getMessage().contains("Invalid digest algorithm"));
        }
    }

    /**
     * Tests that command works when valid digest algorithm is provided.
     */
    @Test
    public void test08ValidDigestAlgorithm() throws Exception {
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-instr",
                "Any text we want to have a timestamp for...123",
                "-url", "http://localhost:8080/signserver/tsa?workerId=" + getSignerIdTimeStampSigner1(), "-digestalgorithm", "SHA-256"));
    }

    /**
     * Tests that command works when digest algorithm is not provided as default digest algorithm (SHA-256) is used.
     */
    @Test
    public void test09DigestAlgorithmNotSpecified() throws Exception {
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-instr",
                "Any text we want to have a timestamp for...123",
                "-url", "http://localhost:8080/signserver/tsa?workerId=" + getSignerIdTimeStampSigner1()));
    }

    /**
     * Tests that command fails when digest algorithm option name is invalid.
     */
    @Test
    public void test10InvalidDigestAlgorithmOptionName() throws Exception {
        assertEquals("Invalid arguments", CommandLineInterface.RETURN_INVALID_ARGUMENTS, cli.execute("timestamp", "-instr",
                "Any text we want to have a timestamp for...123",
                "-url", "http://localhost:8080/signserver/tsa?workerId=" + getSignerIdTimeStampSigner1(), "-digestAlgorithm", "SHA-256"));
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdTimeStampSigner1());
    }
}
