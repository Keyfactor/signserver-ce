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

import static org.junit.Assert.assertEquals;

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
    private final String DENY = "DENY";
    private final String SAMEORIGIN = "SAMEORIGIN";

    @Override
    protected String getServletURL() {
        return baseURL;
    }

    @Before
    public void setUp() {
        baseURL = getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver";
    }

    /**
     * Tests some of the different public web resources.
     */
    @Test
    public void testXFrameOptionsHeaderOnPublicWeb() throws Exception {
        assertHeaderEquals(baseURL + "/", "GET", DENY);
        assertHeaderEquals(baseURL + "/", "POST", DENY);
        assertHeaderEquals(baseURL + "/process", "GET", DENY);
        assertHeaderEquals(baseURL + "/process", "POST", DENY);
        assertHeaderEquals(baseURL + "/worker/_non_existing_", "GET", DENY);
        assertHeaderEquals(baseURL + "/worker/_non_existing_", "POST", DENY);
        assertHeaderEquals(baseURL + "/process", "POST", DENY);
        assertHeaderEquals(baseURL + "/_non_existing_", "GET", DENY);
        assertHeaderEquals(baseURL + "/_non_existing_", "POST", DENY);

        assertHeaderEquals(baseURL + "/demo", "GET", DENY);
        assertHeaderEquals(baseURL + "/demo", "POST", DENY);
        assertHeaderEquals(baseURL + "/demo/_non_existing_", "GET", DENY);
        assertHeaderEquals(baseURL + "/demo/_non_existing_", "POST", DENY);
    }

    /**
     * Tests some of the different documentation resources.
     */
    @Test
    public void testXFrameOptionsHeaderInDoc() throws Exception {
        assertHeaderEquals(baseURL + "/doc", "GET", SAMEORIGIN);
        assertHeaderEquals(baseURL + "/doc", "POST", SAMEORIGIN);
        assertHeaderEquals(baseURL + "/doc/_non_existing_", "GET", SAMEORIGIN);
        assertHeaderEquals(baseURL + "/doc/_non_existing_", "POST", SAMEORIGIN);
    }

    /**
     * Tests some of the different health check resources.
     */
    @Test
    public void testXFrameOptionsHeaderInHealthCheck() throws Exception {
        assertHeaderEquals(baseURL + "/healthcheck", "GET", DENY);
        assertHeaderEquals(baseURL + "/healthcheck", "POST", DENY);
        assertHeaderEquals(baseURL + "/healthcheck/signserverhealth", "GET", DENY);
        assertHeaderEquals(baseURL + "/healthcheck/signserverhealth", "POST", DENY);
        assertHeaderEquals(baseURL + "/healthcheck/_non_existing_", "GET", DENY);
        assertHeaderEquals(baseURL + "/healthcheck/_non_existing_", "POST", DENY);
    }

    /**
     * Sends a request and asserts that the specified HTTP header equals the expected value.
     * @param url to send request to
     * @param method to use
     * @throws IOException IO Exception
     */
    private void assertHeaderEquals(String url, String method, String expected) throws IOException {
        HttpURLConnection conn = null;
        try {
            String message = method + " " + url;
            LOG.info("Testing " + message);
            conn = WebTestCase.send(url, Collections.emptyMap(), method);
            assertEquals(message, expected, conn.getHeaderField("X-FRAME-OPTIONS"));
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

}
