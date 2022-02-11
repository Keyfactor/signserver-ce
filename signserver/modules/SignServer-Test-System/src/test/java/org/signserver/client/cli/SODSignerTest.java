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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.admin.cli.AdminCLI;
import org.signserver.cli.CommandLineInterface;
import org.signserver.common.SignServerUtil;
import org.signserver.module.mrtdsodsigner.jmrtd.SODFile;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.ejb.interfaces.WorkerSession;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for the signdatagroups command of Client CLI.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SODSignerTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SODSignerTest.class);

    /** Worker7897: Default algorithms, default hashing setting */
    private static final int WORKERID = 7897;

    /** Worker 6676: Dummy signer echoing request metadata. */
    private static final int WORKERID2 = 6676;

    private final CLITestHelper adminCLI = new CLITestHelper(AdminCLI.class);
    private final CLITestHelper clientCLI = new CLITestHelper(ClientCLI.class);

    private final WorkerSession workerSession = getWorkerSession();

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @After
    public void tearDown() {
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        LOG.info("test00SetupDatabase");
        addSigner("org.signserver.module.mrtdsodsigner.MRTDSODSigner", WORKERID, "TestMRTDSODSigner1", true);

        // WORKER1 uses a P12 keystore
        workerSession.setWorkerProperty(WORKERID, "KEYSTOREPATH",
                getSignServerHome().getAbsolutePath()
                + File.separator + "res" + File.separator + "test"
                + File.separator + "dss10" + File.separator + "dss10_keystore.p12");
        workerSession.setWorkerProperty(WORKERID, "DEFAULTKEY", "sod00001");
        workerSession.reloadConfiguration(WORKERID);

        // Dummy worker echoing request metadata
        addSigner("org.signserver.server.signers.EchoRequestMetadataSigner", WORKERID2, "EchoRequestMetadataSigner", true);
    }

    @Test
    public void test01missingArguments() throws Exception {
        LOG.info("test01missingArguments");
        assertEquals("missing arguments", CommandLineInterface.RETURN_INVALID_ARGUMENTS,
                clientCLI.execute("signdatagroups"));
    }

    /**
     * Tests the sample use case a from the documentation.
     * <pre>
     * a) signdatagroups -workername MRTDSODSigner -data "1=dmFsdWUxCg==&2=dmFsdWUyCg==&3=dmFsdWUzCg=="
     * </pre>
     */
    @Test
    public void test02signDataFromParameter() throws Exception {
        LOG.info("test02signDataFromParameter");
        workerSession.setWorkerProperty(WORKERID, "DODATAGROUPHASHING", "true");
        workerSession.reloadConfiguration(WORKERID);
        try {
            assertEquals(CommandLineInterface.RETURN_SUCCESS,
                    clientCLI.execute("signdatagroups", "-workername", "TestMRTDSODSigner1", "-data", "1=dmFsdWUxCg==&2=dmFsdWUyCg==&3=dmFsdWUzCg=="));
            String res = clientCLI.getOut().toString();
            assertNotNull("non null result", res);
            assertTrue("non empty result: " + res.length(), res.length() > 50);
        } finally {
            workerSession.setWorkerProperty(WORKERID, "DODATAGROUPHASHING", "false");
            workerSession.reloadConfiguration(WORKERID);
        }
    }

    /**
     * Tests signing using ClientWS.
     * <pre>
     * signdatagroups -workername MRTDSODSigner -data "1=dmFsdWUxCg==&2=dmFsdWUyCg==&3=dmFsdWUzCg==" -protocol CLIENTWS
     * </pre>
     */
    @Test
    public void test02signDataFromParameterOverClientWS() throws Exception {
        LOG.info("test02signDataFromParameterOverClientWS");
        workerSession.setWorkerProperty(WORKERID, "DODATAGROUPHASHING", "true");
        workerSession.reloadConfiguration(WORKERID);
        try {
            assertEquals(CommandLineInterface.RETURN_SUCCESS,
                    clientCLI.execute("signdatagroups", "-workername", "TestMRTDSODSigner1", "-data", "1=dmFsdWUxCg==&2=dmFsdWUyCg==&3=dmFsdWUzCg==", "-protocol", "CLIENTWS",
                            "-truststore", getSignServerHome() + "/p12/truststore.jks", "-truststorepwd", "changeit", "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort())));
            String res = clientCLI.getOut().toString();
            assertNotNull("non null result", res);
            assertTrue("non empty result: " + res.length(), res.length() > 50);
            byte[] resBytes = clientCLI.getOut().toByteArray();
            SODFile sod = new SODFile(new ByteArrayInputStream(resBytes));
            Map<Integer, byte[]> dataGroupHashes = sod.getDataGroupHashes();
            assertEquals("DG1", new String(digestHelper("dmFsdWUxCg==".getBytes())), new String(dataGroupHashes.get(1)));
            assertEquals("DG2", new String(digestHelper("dmFsdWUyCg==".getBytes())), new String(dataGroupHashes.get(2)));
            assertEquals("DG3", new String(digestHelper("dmFsdWUzCg==".getBytes())), new String(dataGroupHashes.get(3)));
        } finally {
            workerSession.setWorkerProperty(WORKERID, "DODATAGROUPHASHING", "false");
            workerSession.reloadConfiguration(WORKERID);
        }
    }

    /**
     * Test signing with an additional metadata parameter.
     */
    @Test
    public void test03signDataMetadata() throws Exception {
        LOG.info("test03signDataMetadata");
        assertEquals(CommandLineInterface.RETURN_SUCCESS,
                clientCLI.execute("signdatagroups", "-workername", "EchoRequestMetadataSigner", "-data", "1=dmFsdWUxCg==&2=dmFsdWUyCg==&3=dmFsdWUzCg==",
                        "-metadata", "foo=bar"));
        final String res = clientCLI.getOut().toString();

        assertTrue("Should contain metadata", res.contains("foo=bar"));
    }

    /**
     * Test signing with several additional metadata parameters.
     */
    @Test
    public void test04signDataMetadataMultipleParams() throws Exception {
        LOG.info("test04signDataMetadataMultipleParams");
        assertEquals(CommandLineInterface.RETURN_SUCCESS,
                clientCLI.execute("signdatagroups", "-workername", "EchoRequestMetadataSigner", "-data", "1=dmFsdWUxCg==&2=dmFsdWUyCg==&3=dmFsdWUzCg==",
                        "-metadata", "foo=bar", "-metadata", "foo2=bar2"));
        final String res = clientCLI.getOut().toString();

        assertTrue("Should contain metadata", res.contains("foo=bar"));
        assertTrue("Should contain metadata", res.contains("foo2=bar2"));
    }

    /**
     * Test signing with additional metadata over client WS.
     */
    @Test
    public void test05signDataMetadataOverClientWS() throws Exception {
        LOG.info("test05signDataMetadataOverClientWS");
        assertEquals(CommandLineInterface.RETURN_SUCCESS,
                clientCLI.execute("signdatagroups", "-workername", "EchoRequestMetadataSigner", "-data", "1=dmFsdWUxCg==&2=dmFsdWUyCg==&3=dmFsdWUzCg==", "-protocol", "CLIENTWS",
                "-truststore", getSignServerHome() + "/p12/truststore.jks", "-truststorepwd", "changeit", "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort()),
                "-metadata", "foo=bar", "-metadata", "foo2=bar2"));
        final String res = clientCLI.getOut().toString();

        assertTrue("Should contain metadata", res.contains("foo=bar"));
        assertTrue("Should contain metadata", res.contains("foo2=bar2"));
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        LOG.info("test99TearDownDatabase");
        assertEquals(CommandLineInterface.RETURN_SUCCESS, adminCLI.execute(
            "removeworker",
            String.valueOf(WORKERID)
        ));
        workerSession.reloadConfiguration(WORKERID);

        assertEquals(CommandLineInterface.RETURN_SUCCESS, adminCLI.execute(
                "removeworker",
                String.valueOf(WORKERID2)
        ));
        workerSession.reloadConfiguration(WORKERID2);
    }

    private byte[] digestHelper(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA256");
        return md.digest(data);
    }
}
