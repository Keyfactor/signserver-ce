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
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.AccessDeniedException;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.testutils.*;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for the RemoteAddressAuthorizer.
 *
 *
 * @author Markus Kilas
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class RemoteAddressAuthorizerTest extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(
            RemoteAddressAuthorizerTest.class);

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Test
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
     * Tests that the worker throws an AccessDeniedException if no
     * ALLOW_FROM is specified.
     * @throws Exception in case of exception
     */
    @Test
    public void test01noAllowFrom() throws Exception {
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));

        assertEquals("HTTP response code", 403, responseCode);
    }

    /**
     * Tests that when localhost is added to the allow from list no
     * exception is thrown.
     * @throws Exception in case of exception
     */
    @Test
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
    @Test
    public void test03RequestFromOther() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(),
                "ALLOW_FROM", "113.113.113.113");
        workerSession.reloadConfiguration(getSignerIdDummy1());

        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));

        assertEquals("HTTP response code", 403, responseCode);
    }

    /**
     * Tests that the request now is allowed as it is
     * added to the list.
     * @throws Exception in case of exception
     */
    @Test
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

    @Test
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
        } catch (AccessDeniedException ex) {
            fail(ex.getMessage());
        } catch (Exception ex) {
            LOG.error("Wrong type of exception", ex);
            fail("Exception: " + ex.getMessage());
        }
    }
    
    /**
     * Test with an additional IPv6 address added to the allow list.
     * 
     * @throws Exception
     */
    @Test
    public void test06RequestWithAdditionalIPv6Address() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(), "ALLOW_FROM",
                "127.0.0.1, 3ffe:1900:4545:3:200:f8ff:fe21:67cf");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));

        assertEquals("HTTP response code", 200, responseCode);
    }
    
    /**
     * Test that allowing literal localhost in IPv6 short-form is allowed when using short-form.
     * 
     * @throws Exception
     */
    @Test
    public void test07RequestIPv6Localhost() throws Exception {
        final RemoteAddressAuthorizer auth = new RemoteAddressAuthorizer();
        
        auth.setAllowFromProperty("::1");
        assertTrue("Allow IPv6 localhost", auth.isAddressAuthorized("::1"));
    }
    
    /**
     * Test that IPv6 localhost in long-form is accepted when configured to accept the short-form.
     * 
     * @throws Exception
     */
    @Test
    public void test08RequestIPv6LocalhostLongForm() throws Exception {
        final RemoteAddressAuthorizer auth = new RemoteAddressAuthorizer();
        
        auth.setAllowFromProperty("::1");
        assertTrue("Allow IPv6 localhost long-form", auth.isAddressAuthorized("0000:0000:0000:0000:0000:0000:0000:0001"));
    }
    
    /**
     * Test that IPv6 localhost in short-form is accepted when configured to accept the long-form.
     * 
     * @throws Exception
     */
    @Test
    public void test09RequestIPv6LocalhostShortForm() throws Exception {
        final RemoteAddressAuthorizer auth = new RemoteAddressAuthorizer();
        
        auth.setAllowFromProperty("0000:0000:0000:0000:0000:0000:0000:0001");
        assertTrue("Allow IPv6 localhost short-form", auth.isAddressAuthorized("::1"));
    }
    
    /**
     * Test that a non-localhost IPv6 address using some contractions is accepted when in the allow list.
     * 
     * @throws Exception
     */
    @Test
    public void test10RequestIPv6Accepted() throws Exception {
        final RemoteAddressAuthorizer auth = new RemoteAddressAuthorizer();
        
        auth.setAllowFromProperty("3ffe:1900:4545:3:200:f8ff:fe21:67cf");
        assertTrue("Allow IPv6 address", auth.isAddressAuthorized("3ffe:1900:4545:3:200:f8ff:fe21:67cf"));
    }
    
    /**
     * Test that an IPv6 address not in the allow list is not accepted.
     * 
     * @throws Exception
     */
    @Test
    public void test11RequestIPv6NotAccepted() throws Exception {
        final RemoteAddressAuthorizer auth = new RemoteAddressAuthorizer();
        
        auth.setAllowFromProperty("3ffe:1900:4545:3:200:f8ff:fe21:67cf");
        assertFalse("Reject other IPv6 address", auth.isAddressAuthorized("3ffe:1900:4545:3:200:f8ff:fe21:77cf"));
    }
    
    /**
     * Test that accepted IPv6 works when there's also an IPv4 address in the allow list.
     * 
     * @throws Exception
     */
    @Test
    public void test12RequestIPv6AcceptedWithIPv4() throws Exception {
        final RemoteAddressAuthorizer auth = new RemoteAddressAuthorizer();
        
        auth.setAllowFromProperty("127.0.0.1, 3ffe:1900:4545:3:200:f8ff:fe21:67cf");
        assertTrue("Allow IPv6 address", auth.isAddressAuthorized("3ffe:1900:4545:3:200:f8ff:fe21:67cf"));
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

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdDummy1());
        workerSession.reloadConfiguration(getSignerIdDummy1());
    }
}
