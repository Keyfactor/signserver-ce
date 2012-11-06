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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import org.apache.log4j.Logger;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.testutils.*;

/**
 * Tests for the RemoteAddressAuthorizer.
 *
 *
 * @author Markus Kilas
 * @version $Id$
 */
public class RemoteAddressAuthorizerTest extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(
            RemoteAddressAuthorizerTest.class);

    @Override
    protected void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Override
    protected void tearDown() throws Exception {
    }

    public void test00SetupDatabase() throws Exception {
        addDummySigner1();

        // Set auth type
        workerSession.setWorkerProperty(getSignerIdDummy1(), "AUTHTYPE",
                "org.signserver.server.RemoteAddressAuthorizer");

        // Remove old property
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "ALLOW_FROM");

        workerSession.reloadConfiguration(getSignerIdDummy1());
    }

    /**
     * Tests that the worker throws an AuthorizationRequiredException if no
     * ALLOW_FROM is specified.
     * @throws Exception in case of exception
     */
    public void test01noAllowFrom() throws Exception {

        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));

        assertTrue("HTTP response code: " + responseCode, responseCode == 401
                || responseCode == 403);
    }

    /**
     * Tests that when localhost is added to the allow from list no
     * exception is thrown.
     * @throws Exception in case of exception
     */
    public void test02RequestFromLocalhost() throws Exception {

        workerSession.setWorkerProperty(getSignerIdDummy1(),
                "ALLOW_FROM", "127.0.0.1");
        workerSession.reloadConfiguration(getSignerIdDummy1());

        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));

        assertEquals("HTTP response code", 200, responseCode);
    }

    /**
     * Tests that access is denied if the request comes from another address
     * then the allowed.
     *
     * @throws Exception in case of exception
     */
    public void test03RequestFromOther() throws Exception {

        workerSession.setWorkerProperty(getSignerIdDummy1(),
                "ALLOW_FROM", "113.113.113.113");
        workerSession.reloadConfiguration(getSignerIdDummy1());

        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));

        assertTrue("HTTP response code: " + responseCode, responseCode == 401
                || responseCode == 403);
    }

    /**
     * Tests that the request now is allowed as it is
     * added to the list.
     * @throws Exception in case of exception
     */
    public void test04RequestFromOtherAllowed() throws Exception {

        workerSession.setWorkerProperty(getSignerIdDummy1(), "ALLOW_FROM",
                "113.113.113.113, 127.0.0.1");
        workerSession.reloadConfiguration(getSignerIdDummy1());

        int responseCode = process(new URL(
                "http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 200, responseCode);

        // First interface should still work
        responseCode = process(new URL(
                "http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 200, responseCode);
    }

    public void test05RequestFromEJB() throws Exception {

        // No address is provided with EJB unless the requestor fills it in
        // manually so add null to be an accepted address
        workerSession.setWorkerProperty(getSignerIdDummy1(), "ALLOW_FROM",
                "127.0.0.1, null, 127.0.1.1");
        workerSession.reloadConfiguration(getSignerIdDummy1());

        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());

        try {
            workerSession.process(getSignerIdDummy1(), request, new RequestContext());
        } catch (AuthorizationRequiredException ex) {
            fail(ex.getMessage());
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }
    }

    /**
     * Tests that access is allowed when using the
     * "ALL" keyword in ALLOW_FROM
     * 
     * @throws Exception
     */
    public void test06RequestAllowAll() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(), "ALLOW_FROM", "ALL");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        final GenericSignRequest request =
                new GenericSignRequest(1, "<root/>".getBytes());
        
        try {
            workerSession.process(getSignerIdDummy1(), request, new RequestContext());
        } catch (AuthorizationRequiredException ex) {
            fail(ex.getMessage());
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }
    }

    /**
     * Test that access is denied when setting the ALLOW_X_FORWARDED_FOR property and not including
     * the address in the X-Forwarded-For header
     * 
     * @throws Exception
     */
    public void test07RequestWithXForwardedFor() throws Exception {
        // allow localhost (simulate a proxy...)
        workerSession.setWorkerProperty(getSignerIdDummy1(), "ALLOW_FROM", "127.0.0.1");
        workerSession.setWorkerProperty(getSignerIdDummy1(), "ALLOW_FORWARDED_FROM", "1.2.3.4");
        workerSession.reloadConfiguration(getSignerIdDummy1());
               
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                    + "/signserver/process?workerId="
                    + getSignerIdDummy1() + "&data=%3Croot/%3E"), "42.42.42.42");

        assertTrue("HTTP response code: " + responseCode, responseCode == 401
                    || responseCode == 403);
    }
    
    private int process(URL workerUrl, final String forwardIPs) {
        int responseCode = -1;

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) workerUrl.openConnection();
            conn.setAllowUserInteraction(false);
            conn.setRequestMethod("GET");
            conn.setDoOutput(false);
            conn.setReadTimeout(2000);
            if (forwardIPs != null) {
                conn.addRequestProperty(RequestContext.X_FORWARDED_FOR, forwardIPs);
            }
            responseCode = conn.getResponseCode();
        } catch (IOException ex) {
            LOG.error(ex);
        }
        return responseCode;
    }
    
    private int process(URL workerUrl) {
        return process(workerUrl, null);
    }

    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
        workerSession.reloadConfiguration(getSignerIdDummy1());
    }
}
