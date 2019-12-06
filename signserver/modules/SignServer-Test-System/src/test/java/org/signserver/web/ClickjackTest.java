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
package org.signserver.web;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Collections;
import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.signserver.testutils.WebTestCase;

/**
 * Tests that the ClickJackFilter is enabled for the various web modules.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ClickjackTest extends WebTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ClickjackTest.class);

    private String baseURL;

    @Override
    protected String getServletURL() {
        return baseURL;
    }

    @Before
    @Override
    public void setUp() {
        baseURL = getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver";
    }

    /**
     * Tests some of the different public web resources.
     * @throws Exception 
     */
    @Test
    public void testXFrameOptionsHeaderOnPublicWeb() throws Exception {
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/", "GET");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/", "POST");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/process", "GET");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/process", "POST");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/worker/_non_existing_", "GET");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/worker/_non_existing_", "POST");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/process", "POST");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/_non_existing_", "GET");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/_non_existing_", "POST");

        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/demo", "GET");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/demo", "POST");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/demo/_non_existing_", "GET");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/demo/_non_existing_", "POST");
    }

    /**
     * Tests some of the different documentation resources.
     * @throws Exception 
     */
    @Test
    public void testXFrameOptionsHeaderInDoc() throws Exception {
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/doc", "GET");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/doc", "POST");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/doc/_non_existing_", "GET");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/doc/_non_existing_", "POST");
    }

    /**
     * Tests some of the different health check resources.
     * @throws Exception 
     */
    @Test
    public void testXFrameOptionsHeaderInHealthCheck() throws Exception {
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/healthcheck", "GET");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/healthcheck", "POST");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/healthcheck/signserverhealth", "GET");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/healthcheck/signserverhealth", "POST");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/healthcheck/_non_existing_", "GET");
        assertHeaderEquals("X-FRAME-OPTIONS", "DENY", baseURL + "/healthcheck/_non_existing_", "POST");
    }

    /**
     * Sends a request and asserts that the specified HTTP header equals the expected value.
     * @param header to check
     * @param expected value
     * @param url to send request to
     * @param method to use
     * @throws IOException 
     */
    private void assertHeaderEquals(String header, String expected, String url, String method) throws IOException {
        HttpURLConnection conn = null;
        try {
            String message = method + " " + url;
            LOG.info("Testing " + message);
            conn = WebTestCase.send(url, Collections.<String, String>emptyMap(), method);
            assertEquals(message, expected, conn.getHeaderField(header));
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

}
