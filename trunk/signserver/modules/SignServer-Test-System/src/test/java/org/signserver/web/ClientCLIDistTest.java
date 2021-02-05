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

import org.signserver.testutils.WebTestCase;
import org.apache.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for the download of a ClientCLI binary distribution from the public
 * web pages.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ClientCLIDistTest extends WebTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ClientCLIDistTest.class);

    private String pageURL;

    public ClientCLIDistTest() {
    }

    @Override
    protected String getServletURL() {
        return pageURL;
    }

    /** Tests that there is an link to the download page on the front page. */
    @Test
    public void testFirstPageClientCLILinkAvailable() throws Exception {
        this.pageURL = getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver/";
        final String body = new String(sendAndReadyBody(NO_FIELDS));
        assertTrue("Contains <a href=\"clientcli-dist/\">: " + body, body.contains("<a href=\"clientcli-dist/\">"));
    }

    /** Tests that there is an download link on the download page. */
    @Test
    public void testClientCLIPageDownloadLinkAvailable() throws Exception {
        LOG.info("This test assumes web.clientcli.dist.enabled=true in signserver_deploy.properties");
        this.pageURL = getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver/clientcli-dist/";
        final String body = new String(sendAndReadyBody(NO_FIELDS));
        assertTrue("Contains <a href=\"signserver-clientcli.zip\">: " + body, body.contains("<a href=\"signserver-clientcli.zip\">"));
    }

    /** Tests that the AdminGUI zip can be downloaded. */
    @Test
    public void testClientCLIPageDownload() {
        LOG.info("This test assumes web.clientcli.dist.enabled=true in signserver_deploy.properties");
        this.pageURL = getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver/clientcli-dist/signserver-clientcli.zip";
        assertStatusReturned(NO_FIELDS, 200);
    }
}
