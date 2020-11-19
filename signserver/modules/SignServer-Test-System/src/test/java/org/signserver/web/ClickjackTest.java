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
        assertHeaderEquals(baseURL + "/", "GET");
        assertHeaderEquals(baseURL + "/", "POST");
        assertHeaderEquals(baseURL + "/process", "GET");
        assertHeaderEquals(baseURL + "/process", "POST");
        assertHeaderEquals(baseURL + "/worker/_non_existing_", "GET");
        assertHeaderEquals(baseURL + "/worker/_non_existing_", "POST");
        assertHeaderEquals(baseURL + "/process", "POST");
        assertHeaderEquals(baseURL + "/_non_existing_", "GET");
        assertHeaderEquals(baseURL + "/_non_existing_", "POST");

        assertHeaderEquals(baseURL + "/demo", "GET");
        assertHeaderEquals(baseURL + "/demo", "POST");
        assertHeaderEquals(baseURL + "/demo/_non_existing_", "GET");
        assertHeaderEquals(baseURL + "/demo/_non_existing_", "POST");
    }

    /**
     * Tests some of the different documentation resources.
     */
    @Test
    public void testXFrameOptionsHeaderInDoc() throws Exception {
        assertHeaderEquals(baseURL + "/doc", "GET");
        assertHeaderEquals(baseURL + "/doc", "POST");
        assertHeaderEquals(baseURL + "/doc/_non_existing_", "GET");
        assertHeaderEquals(baseURL + "/doc/_non_existing_", "POST");
    }

    /**
     * Tests some of the different health check resources.
     */
    @Test
    public void testXFrameOptionsHeaderInHealthCheck() throws Exception {
        assertHeaderEquals(baseURL + "/healthcheck", "GET");
        assertHeaderEquals(baseURL + "/healthcheck", "POST");
        assertHeaderEquals(baseURL + "/healthcheck/signserverhealth", "GET");
        assertHeaderEquals(baseURL + "/healthcheck/signserverhealth", "POST");
        assertHeaderEquals(baseURL + "/healthcheck/_non_existing_", "GET");
        assertHeaderEquals(baseURL + "/healthcheck/_non_existing_", "POST");
    }

    /**
     * Sends a request and asserts that the specified HTTP header equals the expected value.
     * @param url to send request to
     * @param method to use
     * @throws IOException IO Exception
     */
    private void assertHeaderEquals(String url, String method) throws IOException {
        HttpURLConnection conn = null;
        try {
            String message = method + " " + url;
            LOG.info("Testing " + message);
            conn = WebTestCase.send(url, Collections.emptyMap(), method);
            assertEquals(message, "DENY", conn.getHeaderField("X-FRAME-OPTIONS"));
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

}
