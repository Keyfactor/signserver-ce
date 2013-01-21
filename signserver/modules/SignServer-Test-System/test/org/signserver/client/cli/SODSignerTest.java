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
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.signserver.admin.cli.AdminCLI;
import org.signserver.cli.CommandLineInterface;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.module.mrtdsodsigner.jmrtd.SODFile;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Tests for the signdatagroups command of Client CLI.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SODSignerTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SODSignerTest.class);

    /** Worker7897: Default algorithms, default hashing setting */
    private static final int WORKERID = 7897;

    private static IWorkerSession.IRemote workerSession;
    private static File signServerHome;
    
    private CLITestHelper adminCLI = new CLITestHelper(AdminCLI.class);
    private CLITestHelper clientCLI = new CLITestHelper(ClientCLI.class);
	
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
        workerSession = ServiceLocator.getInstance().lookupRemote(
                IWorkerSession.IRemote.class);
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
    }

    protected File getSignServerHome() throws Exception {
        if (signServerHome == null) {
            final String home = System.getenv("SIGNSERVER_HOME");
            assertNotNull("SIGNSERVER_HOME", home);
            signServerHome = new File(home);
            assertTrue("SIGNSERVER_HOME exists", signServerHome.exists());
        }
        return signServerHome;
    }
	
    public void test00SetupDatabase() throws Exception {

        assertEquals(CommandLineInterface.RETURN_SUCCESS, 
                adminCLI.execute("setproperties", getSignServerHome().getAbsolutePath() + "/modules/SignServer-Module-MRTDSODSigner/src/conf/junittest-part-config.properties"));

        // WORKER1 uses a P12 keystore
        workerSession.setWorkerProperty(WORKERID, "KEYSTOREPATH",
                getSignServerHome().getAbsolutePath()
                + File.separator + "res" + File.separator + "test"
                + File.separator + "demods1.p12");
        workerSession.setWorkerProperty(WORKERID, "KEYSTOREPASSWORD", "foo123");

        workerSession.reloadConfiguration(WORKERID);
    }

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
    public void test02signDataFromParameterOverClientWS() throws Exception {
        assertEquals(CommandLineInterface.RETURN_SUCCESS, 
                clientCLI.execute("signdatagroups", "-workername", "TestMRTDSODSigner1", "-data", "1=value1&2=value2&3=value3", "-protocol", "CLIENTWS", 
                "-truststore", getSignServerHome() + "/p12/truststore.jks", "-truststorepwd", "changeit"));
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

    public void test99TearDownDatabase() throws Exception {
        assertEquals(CommandLineInterface.RETURN_SUCCESS, adminCLI.execute(
            "removeworker",
            String.valueOf(WORKERID)
        ));
        workerSession.reloadConfiguration(WORKERID);
    }
}
