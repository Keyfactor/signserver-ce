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

import static io.restassured.RestAssured.given;
import io.restassured.config.RestAssuredConfig;
import io.restassured.http.Method;
import org.apache.log4j.Logger;
import org.junit.Test;
import org.signserver.testutils.ModulesTestCase;

/**
 * System test for the allowed-host-checker in the application server.
 *
 * This test assumes undertow configured with ab allowed host checker filter
 * that at least accepts httpserver.hostname and the httpserver.pubhttp port and 
 * not bad.example.org:
 * <pre>
 * &lt;filters&gt;
 *     &lt;expression-filter name="allowed-host-checker" expression="not(contains(search={localhost:8080,localhost:8442,localhost:8443}, value=%{i,host})) -&gt; response-code(403)"/&gt;
 * &lt;/filters&gt;
 * </pre>
 * 
 */
public class AllowedHostCheckerTest extends ModulesTestCase {

    private static final Logger LOG = Logger.getLogger(AllowedHostCheckerTest.class);

    /**
     * Tests with an allowed host.
     * @throws Exception in case of error
     */
    @Test
    public void testGetAllowedHost() throws Exception {
        LOG.debug("testGetAllowedHost");

        final String baseURL = "http://" + getHTTPHost() + ":" + getPublicHTTPPort() + "/signserver/";
        given()
            .header("X-Keyfactor-Requested-With", "1")
            .config(new RestAssuredConfig())
            .when()
            .request(Method.GET, baseURL + "")
            .then()
            .statusCode(200);
    }

    /**
     * Tests with bad.example.org as hosts header and should be rejected.
     * @throws Exception in case of error
     */
    @Test
    public void testGetNotAllowedHost() throws Exception {
        LOG.debug("testGetNotAllowedHost");

        final String baseURL = "http://" + getHTTPHost()+ ":" + getPublicHTTPPort() + "/signserver/";

        given()
            .header("host", "bad.example.org")
            .header("X-Keyfactor-Requested-With", "1")
            .config(new RestAssuredConfig())
            .when()
            .request(Method.GET, baseURL + "")
            .then()
            .statusCode(403);
    }

}
