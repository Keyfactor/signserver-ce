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
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.module.mrtdsodsigner.jmrtd.SODFile;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestingSecurityManager;

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

    private final IWorkerSession workerSession = getWorkerSession();
    
    @Before
    @Override
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @After
    @Override
    public void tearDown() throws Exception {
        TestingSecurityManager.remove();
    }
	
    @Test
    public void test00SetupDatabase() throws Exception {

        assertEquals(CommandLineInterface.RETURN_SUCCESS, 
                adminCLI.execute("setproperties", getSignServerHome().getAbsolutePath() + "/res/test/test-mrtdsodsigner-configuration.properties"));

        // WORKER1 uses a P12 keystore
        workerSession.setWorkerProperty(WORKERID, "KEYSTOREPATH",
                getSignServerHome().getAbsolutePath()
                + File.separator + "res" + File.separator + "test"
                + File.separator + "demods1.p12");
        workerSession.setWorkerProperty(WORKERID, "KEYSTOREPASSWORD", "foo123");
        workerSession.reloadConfiguration(WORKERID);
        
        // Dummy worker echoing request metadata
        assertEquals(CommandLineInterface.RETURN_SUCCESS, 
                adminCLI.execute("setproperties", getSignServerHome().getAbsolutePath() + "/res/test/test-echometadata-configuration.properties"));
        workerSession.reloadConfiguration(WORKERID2);
    }

    @Test
    public void test01missingArguments() throws Exception {
        assertEquals("missing arguments", CommandLineInterface.RETURN_INVALID_ARGUMENTS, 
                clientCLI.execute("signdatagroups"));
    }

    /**
     * Tests the sample use case a from the documentation.
     * <pre>
     * a) signdatagroups -workername MRTDSODSigner -data "1=value1&2=value2&3=value3"
     * </pre>
     * @throws Exception
     */
    @Test
    public void test02signDataFromParameter() throws Exception {
        assertEquals(CommandLineInterface.RETURN_SUCCESS, 
                clientCLI.execute("signdatagroups", "-workername", "TestMRTDSODSigner1", "-data", "1=value1&2=value2&3=value3"));
        String res = clientCLI.getOut().toString();
        assertNotNull("non null result", res);
        assertTrue("non empty result: " + res.length(), res.length() > 50);
    }
    
    /**
     * Tests signing using ClientWS.
     * <pre>
     * signdatagroups -workername MRTDSODSigner -data "1=value1&2=value2&3=value3" -protocol CLIENTWS
     * </pre>
     * @throws Exception
     */
    @Test
    public void test02signDataFromParameterOverClientWS() throws Exception {
        assertEquals(CommandLineInterface.RETURN_SUCCESS, 
                clientCLI.execute("signdatagroups", "-workername", "TestMRTDSODSigner1", "-data", "1=value1&2=value2&3=value3", "-protocol", "CLIENTWS", 
                "-truststore", getSignServerHome() + "/p12/truststore.jks", "-truststorepwd", "changeit", "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort())));
        String res = clientCLI.getOut().toString();
        assertNotNull("non null result", res);
        assertTrue("non empty result: " + res.length(), res.length() > 50);
        byte[] resBytes = clientCLI.getOut().toByteArray();
        SODFile sod = new SODFile(new ByteArrayInputStream(resBytes));
        Map<Integer, byte[]> dataGroupHashes = sod.getDataGroupHashes();
        assertEquals("DG1", "value1", new String(dataGroupHashes.get(1)));
        assertEquals("DG2", "value2", new String(dataGroupHashes.get(2)));
        assertEquals("DG3", "value3", new String(dataGroupHashes.get(3)));
    }

    /**
     * Test signing with an additional metadata parameter.
     * 
     * @throws Exception
     */
    @Test
    public void test03signDataMetadata() throws Exception {
        assertEquals(CommandLineInterface.RETURN_SUCCESS, 
                clientCLI.execute("signdatagroups", "-workername", "EchoRequestMetadataSigner", "-data", "1=value1&2=value2&3=value3",
                        "-metadata", "foo=bar"));
        final String res = clientCLI.getOut().toString();
    
        assertTrue("Should contain metadata", res.contains("foo=bar"));
    }
    
    /**
     * Test signing with several additional metadata parameters.
     * 
     * @throws Exception
     */
    @Test
    public void test04signDataMetadataMultipleParams() throws Exception {
        assertEquals(CommandLineInterface.RETURN_SUCCESS, 
                clientCLI.execute("signdatagroups", "-workername", "EchoRequestMetadataSigner", "-data", "1=value1&2=value2&3=value3",
                        "-metadata", "foo=bar", "-metadata", "foo2=bar2"));
        final String res = clientCLI.getOut().toString();
    
        assertTrue("Should contain metadata", res.contains("foo=bar"));
        assertTrue("Should contain metadata", res.contains("foo2=bar2"));
    }
    
    /**
     * Test signing with additional metadata over client WS.
     * 
     * @throws Exception
     */
    @Test
    public void test05signDataMetadataOverClientWS() throws Exception {
        assertEquals(CommandLineInterface.RETURN_SUCCESS, 
                clientCLI.execute("signdatagroups", "-workername", "EchoRequestMetadataSigner", "-data", "1=value1&2=value2&3=value3", "-protocol", "CLIENTWS", 
                "-truststore", getSignServerHome() + "/p12/truststore.jks", "-truststorepwd", "changeit", "-host", getHTTPHost(), "-port", String.valueOf(getPublicHTTPSPort()),
                "-metadata", "foo=bar", "-metadata", "foo2=bar2"));
        final String res = clientCLI.getOut().toString();
        
        assertTrue("Should contain metadata", res.contains("foo=bar"));
        assertTrue("Should contain metadata", res.contains("foo2=bar2"));
    }
    
    @Test
    public void test99TearDownDatabase() throws Exception {
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
}
