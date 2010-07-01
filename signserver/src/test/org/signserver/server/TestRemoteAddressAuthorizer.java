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
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.InitialContext;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

/**
 * Tests for the RemoteAddressAuthorizer.
 *
 *
 * @author Markus Kilas
 * @version $Id: TestUsernamePasswordAuthorizer.java 897 2010-03-21 10:38:48Z netmackan $
 */
public class TestRemoteAddressAuthorizer extends TestCase {

    private static final Logger LOG = Logger.getLogger(
            TestRemoteAddressAuthorizer.class);

    private static IWorkerSession.IRemote workSession;
    private static File signServerHome;
    private static int moduleVersion;

    /** 
     * WORKERID used in this test case as defined in 
     * junittest-part-config.properties
     */
    private static final int WORKERID = 5676;

    @Override
    protected void setUp() throws Exception {
        SignServerUtil.installBCProvider();
        final Context context = getInitialContext();
        workSession = (IWorkerSession.IRemote) context.lookup(
                IWorkerSession.IRemote.JNDI_NAME);
        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
        TestingSecurityManager.install();
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

        // Set auth type
        workSession.setWorkerProperty(WORKERID, "AUTHTYPE",
                "org.signserver.server.RemoteAddressAuthorizer");

        // Remove old property
        workSession.removeWorkerProperty(WORKERID, "ALLOW_FROM");
        
        workSession.reloadConfiguration(WORKERID);
    }

    /**
     * Tests that the worker throws an AuthorizationRequiredException if no
     * ALLOW_FROM is specified.
     * @throws Exception in case of exception
     */
    public void test01noAllowFrom() throws Exception {

        int responseCode = process(
                new URL("http://localhost:8080/signserver/process?workerId="
                + WORKERID + "&data=%3Croot/%3E"));

        assertTrue("HTTP response code: " + responseCode, responseCode == 401
                || responseCode == 403);
    }

    /**
     * Tests that when localhost is added to the allow from list no
     * exception is thrown.
     * @throws Exception in case of exception
     */
    public void test02RequestFromLocalhost() throws Exception {

        workSession.setWorkerProperty(WORKERID, "ALLOW_FROM", "127.0.0.1");
        workSession.reloadConfiguration(WORKERID);

        int responseCode = process(
                new URL("http://localhost:8080/signserver/process?workerId="
                + WORKERID + "&data=%3Croot/%3E"));

        assertEquals("HTTP response code", 200, responseCode);
    }

    /**
     * Tests that access is denied if the request comes from another address
     * then the allowed.
     *
     * @throws Exception in case of exception
     */
    public void test03RequestFromOther() throws Exception {

        workSession.setWorkerProperty(WORKERID, "ALLOW_FROM", "113.113.113.113");
        workSession.reloadConfiguration(WORKERID);

        int responseCode = process(
                    new URL("http://localhost:8080/signserver/process?workerId="
                + WORKERID + "&data=%3Croot/%3E"));

        assertTrue("HTTP response code: " + responseCode, responseCode == 401
                || responseCode == 403);
    }

    /**
     * Tests that the request now is allowed as it is
     * added to the list.
     * @throws Exception in case of exception
     */
    public void test04RequestFromOtherAllowed() throws Exception {

        workSession.setWorkerProperty(WORKERID, "ALLOW_FROM",
                "113.113.113.113, 127.0.0.1");
        workSession.reloadConfiguration(WORKERID);

        int responseCode = process(new URL(
                "http://localhost:8080/signserver/process?workerId="
                + WORKERID + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 200, responseCode);

        // First interface should still work
        responseCode = process(new URL(
                "http://localhost:8080/signserver/process?workerId="
                + WORKERID + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 200, responseCode);
    }

    public void test05RequestFromEJB() throws Exception {

        // No address is provided with EJB unless the requestor fills it in
        // manually so add null to be an accepted address
        workSession.setWorkerProperty(WORKERID, "ALLOW_FROM",
                "127.0.0.1, null, 127.0.1.1");
        workSession.reloadConfiguration(WORKERID);

        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        try {
             workSession.process(WORKERID, request, new RequestContext());
        } catch (AuthorizationRequiredException ex) {
            fail(ex.getMessage());
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }
    }

    private int process(URL workerUrl) {
        int responseCode = -1;

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) workerUrl.openConnection();
            conn.setAllowUserInteraction(false);
            conn.setRequestMethod("GET");
            conn.setDoOutput(false);
            conn.setReadTimeout(2000);
            responseCode = conn.getResponseCode();
        } catch (IOException ex) {
            LOG.error(ex);
        }
        return responseCode;
    }

    public void test99TearDownDatabase() throws Exception {
        TestUtils.assertSuccessfulExecution(new String[] {
            "removeworker",
            String.valueOf(WORKERID)
        });

        TestUtils.assertSuccessfulExecution(new String[] {
            "module",
            "remove",
            "XMLSIGNER",
            String.valueOf(moduleVersion)
        });
        assertTrue("module remove",
                TestUtils.grepTempOut("Removal of module successful."));
        workSession.reloadConfiguration(WORKERID);
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

    /**
     * Get the initial naming context
     */
    protected Context getInitialContext() throws Exception {
        Hashtable<String, String> props = new Hashtable<String, String>();
        props.put(
                Context.INITIAL_CONTEXT_FACTORY,
                "org.jnp.interfaces.NamingContextFactory");
        props.put(
                Context.URL_PKG_PREFIXES,
                "org.jboss.naming:org.jnp.interfaces");
        props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
        Context ctx = new InitialContext(props);
        return ctx;
    }
}
