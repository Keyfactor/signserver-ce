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
package org.signserver.server;

import java.io.File;
import java.security.cert.Certificate;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.ServiceLocator;
import org.signserver.common.SignServerUtil;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.TestUtils;

/**
 * Tests limits for the key usages.
 *
 * @author Markus Kilas
 * @version $Id: TestFirstActiveDispatcher.java 950 2010-04-17 19:36:04Z netmackan $
 */
public class TestLimitKeyUsages extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            TestLimitKeyUsages.class);

    private static IGlobalConfigurationSession.IRemote confSession;
    private static IWorkerSession.IRemote workSession;
    private static File signServerHome;
    private static int moduleVersion;

    /** WORKERID used in this test case. */
    private static final int WORKERID_1 = 5802;

    /**
     * Test with this number of signings.
     */
    private static final int LIMIT = 10;


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

        workSession.setWorkerProperty(WORKERID_1, "KEYUSAGELIMIT",
                String.valueOf(LIMIT));

        workSession.reloadConfiguration(WORKERID_1);
    }

    /**
     * Do signings up to KEYUSAGELIMIT and then check that the next signing
     * fails.
     *
     * Assumption 1: The database or atleast the table KeyUsageCounter needs to
     * be cleared.
     * Assumption 2: The configured key (test_keyusagelimit1.p12) is not used by
     * any other tests.
     *
     * @throws Exception in case of exception
     */
    public void test01Limit() throws Exception {

        // Do a number of signings LIMIT
        try {
            for (int i = 0; i < LIMIT; i++) {
                LOG.debug("Signing " + i);
                doSign();
            }
        } catch (CryptoTokenOfflineException ex) {
            fail(ex.getMessage());
        }

        try {
            doSign();
            fail("Should have failed now");

        } catch (CryptoTokenOfflineException ok) {}
    }

    public void test02NoIncreaseWhenOffline() throws Exception {

        // ASSUMPTION: Key usages is now 10

        // Increase key usage limit so we should be able to do two more signings
        workSession.setWorkerProperty(WORKERID_1, "KEYUSAGELIMIT",
                String.valueOf(LIMIT + 2));
        workSession.reloadConfiguration(WORKERID_1);

        // Do one signing just to see that it works
        doSign();

        // Make the signer offline and do one signing that should not increase
        //counter, which means that after activating it again we should be able
        //to do one more signing
        workSession.deactivateSigner(WORKERID_1);
        doSignOffline();

        // Should be able to do one signing now
        workSession.activateSigner(WORKERID_1, "foo123");
        doSign();
    }

    /** Do a dummy sign. */
    private static void doSign() throws Exception {

        final RequestContext context = new RequestContext();
        final GenericSignRequest request = new GenericSignRequest(1,
                "<root/>".getBytes());
        GenericSignResponse res;
        // Send request to dispatcher
        res = (GenericSignResponse) workSession.process(WORKERID_1,
            request, context);
        Certificate cert = res.getSignerCertificate();
        assertNotNull(cert);
    }

    /** Do a dummy sign and expect failure. */
    private static void doSignOffline() throws Exception {

        try {
            final RequestContext context = new RequestContext();
            final GenericSignRequest request = new GenericSignRequest(1,
                    "<root/>".getBytes());
            // Send request to dispatcher
            workSession.process(WORKERID_1,
                request, context);
        } catch (CryptoTokenOfflineException ok) {
            // OK
        } catch (Exception ex) {
            LOG.error("Signer offline but other exception", ex);
            fail("Signer offline but other exception: " + ex.getMessage());
        }
    }

    public void test99TearDownDatabase() throws Exception {

        TestUtils.assertSuccessfulExecution(new String[] {
            "removeworker",
            String.valueOf(WORKERID_1)
        });
        TestUtils.assertSuccessfulExecution(new String[] {
            "module",
            "remove",
            "XMLSIGNER",
            String.valueOf(moduleVersion)
        });
        assertTrue("module remove",
                TestUtils.grepTempOut("Removal of module successful."));

        workSession.reloadConfiguration(WORKERID_1);
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
