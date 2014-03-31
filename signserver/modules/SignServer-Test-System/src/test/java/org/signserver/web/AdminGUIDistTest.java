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

import org.apache.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for the download of an AdminGUI binary distribution from the public
 * web pages.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AdminGUIDistTest extends WebTestCase {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(AdminGUIDistTest.class);
    
    private String pageURL;
    
    public AdminGUIDistTest() {
    }
    
    @Override
    protected String getServletURL() {
        return pageURL;
    }

    /** Tests that there is an link to the download page on the front page. */
    @Test
    public void testFirstPageAdminGUILinkAvailable() throws Exception {
        this.pageURL = getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver/";
        final String body = new String(sendAndReadyBody(NO_FIELDS));
        assertTrue("Contains <a href=\"admingui-dist/\">: " + body, body.contains("<a href=\"admingui-dist/\">"));
    }

    /** Tests that there is an download link on the download page. */
    @Test
    public void testAdminGUIPageDownloadLinkAvailable() throws Exception {
        LOG.info("This test assumes web.admingui.dist.enabled=true in signserver_build.properties");
        this.pageURL = getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver/admingui-dist/";
        final String body = new String(sendAndReadyBody(NO_FIELDS));
        assertTrue("Contains <a href=\"signserver-admingui.zip\">: " + body, body.contains("<a href=\"signserver-admingui.zip\">"));
    }
    
    /** Tests that the AdminGUI zip can be downloaded. */
    @Test
    public void testAdminGUIPageDownload() throws Exception {
        LOG.info("This test assumes web.admingui.dist.enabled=true in signserver_build.properties");
        this.pageURL = getPreferredHTTPProtocol() + getHTTPHost() + ":" + getPreferredHTTPPort() + "/signserver/admingui-dist/signserver-admingui.zip";
        assertStatusReturned(NO_FIELDS, 200);
    }
}
