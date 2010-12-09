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
package org.signserver.server.dispatchers;

import java.io.File;
import java.security.cert.X509Certificate;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.ServiceLocator;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.TestUtils;

/**
 * Tests for the FirstActiveDispatcher.
 *
 *
 * @author Markus Kilas
 * @version $Id$
 */
public class FirstActiveDispatcherTest extends TestCase {

    private static final Logger LOG = Logger.getLogger(
            FirstActiveDispatcherTest.class);

    private static IGlobalConfigurationSession.IRemote confSession;
    private static IWorkerSession.IRemote workSession;
    private static File signServerHome;
    private static int moduleVersion;

    /**
     * WORKERID used in this test case as defined in
     * junittest-part-config.properties.
     */
    private static final int WORKERID_DISPATCHER = 5680;
    private static final int WORKERID_1 = 5681;
    private static final int WORKERID_2 = 5682;
    private static final int WORKERID_3 = 5683;

    @Override
    protected void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        confSession = ServiceLocator.getInstance().lookupRemote(
                        IGlobalConfigurationSession.IRemote.class);
        workSession = ServiceLocator.getInstance().lookupRemote(
                        IWorkerSession.IRemote.class);
        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
        CommonAdminInterface.BUILDMODE = "SIGNSERVER";
    }

    @Override
    protected void tearDown() throws Exception {
    }

    public void test00SetupDatabase() throws Exception {

        System.out.println("File: " + getSignServerHome()
                + "/dist-server/xmlsigner.mar");

        final MARFileParser marFileParser = new MARFileParser(getSignServerHome()
                + "/dist-server/xmlsigner.mar");
        moduleVersion = marFileParser.getVersionFromMARFile();

        TestUtils.assertSuccessfulExecution(new String[] {
                "module",
                "add",
                getSignServerHome() + "/dist-server/xmlsigner.mar",
                "junittest"
            });
        assertTrue("Loading module",
                TestUtils.grepTempOut("Loading module XMLSIGNER"));
        assertTrue("Module loaded",
                TestUtils.grepTempOut("Module loaded successfully."));

        workSession.reloadConfiguration(WORKERID_DISPATCHER);
        workSession.reloadConfiguration(WORKERID_1);
        workSession.reloadConfiguration(WORKERID_2);
        workSession.reloadConfiguration(WORKERID_3);
    }

    /**
     * Tests that requests sent to the dispatching worker are forwarded to
     * any of the configured workers.
     * @throws Exception in case of exception
     */
    public void test01Dispatched() throws Exception {

        final RequestContext context = new RequestContext();

        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        GenericSignResponse res;

        // Send request to dispatcher
        res = (GenericSignResponse) workSession.process(WORKERID_DISPATCHER,
                request, context);
        
        X509Certificate cert = (X509Certificate) res.getSignerCertificate();
        assertTrue("Response from signer 81, 82 or 83",
            cert.getSubjectDN().getName().contains("testdocumentsigner81")
            || cert.getSubjectDN().getName().contains("testdocumentsigner82")
            || cert.getSubjectDN().getName().contains("testdocumentsigner83"));

        // Disable signer 81
        workSession.setWorkerProperty(WORKERID_1, "DISABLED", "TRUE");
        workSession.reloadConfiguration(WORKERID_1);

        // Send request to dispatcher
        res = (GenericSignResponse) workSession.process(WORKERID_DISPATCHER,
                request, context);

        cert = (X509Certificate) res.getSignerCertificate();
        assertTrue("Response from signer 82 or 83",
            cert.getSubjectDN().getName().contains("testdocumentsigner82")
            || cert.getSubjectDN().getName().contains("testdocumentsigner83"));

        // Disable signer 83
        workSession.setWorkerProperty(WORKERID_3, "DISABLED", "TRUE");
        workSession.reloadConfiguration(WORKERID_3);

        // Send request to dispatcher
        res = (GenericSignResponse) workSession.process(WORKERID_DISPATCHER,
                request, context);

        cert = (X509Certificate) res.getSignerCertificate();
        assertTrue("Response from signer 82",
            cert.getSubjectDN().getName().contains("testdocumentsigner82"));

        // Disable signer 82
        workSession.setWorkerProperty(WORKERID_2, "DISABLED", "TRUE");
        workSession.reloadConfiguration(WORKERID_2);

        // Send request to dispatcher
        try {
            res = (GenericSignResponse) workSession.process(WORKERID_DISPATCHER,
                request, context);
            fail("Should have got CryptoTokenOfflineException");
        } catch(CryptoTokenOfflineException ex) {
            // OK
        }

        // Enable signer 81
        workSession.setWorkerProperty(WORKERID_1, "DISABLED", "FALSE");
        workSession.reloadConfiguration(WORKERID_1);

        // Send request to dispatcher
        res = (GenericSignResponse) workSession.process(WORKERID_DISPATCHER,
                request, context);

        cert = (X509Certificate) res.getSignerCertificate();
        assertTrue("Response from signer 81",
            cert.getSubjectDN().getName().contains("testdocumentsigner81"));
    }



    public void test99TearDownDatabase() throws Exception {

        TestUtils.assertSuccessfulExecution(new String[] {
            "removeworker",
            String.valueOf(WORKERID_DISPATCHER)
        });
        TestUtils.assertSuccessfulExecution(new String[] {
            "removeworker",
            String.valueOf(WORKERID_1)
        });
        TestUtils.assertSuccessfulExecution(new String[] {
            "removeworker",
            String.valueOf(WORKERID_2)
        });
        TestUtils.assertSuccessfulExecution(new String[] {
            "removeworker",
            String.valueOf(WORKERID_3)
        });

        TestUtils.assertSuccessfulExecution(new String[] {
            "module",
            "remove",
            "XMLSIGNER",
            String.valueOf(moduleVersion)
        });
        assertTrue("module remove",
                TestUtils.grepTempOut("Removal of module successful."));
        workSession.reloadConfiguration(WORKERID_DISPATCHER);
        workSession.reloadConfiguration(WORKERID_1);
        workSession.reloadConfiguration(WORKERID_2);
        workSession.reloadConfiguration(WORKERID_3);
    }

    private File getSignServerHome() throws Exception {
        if (signServerHome == null) {
            final String home = System.getenv("SIGNSERVER_HOME");
            assertNotNull("SIGNSERVER_HOME", home);
            signServerHome = new File(home);
            assertTrue("SIGNSERVER_HOME exists", signServerHome.exists());
        }
        return signServerHome;
    }
}
