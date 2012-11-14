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
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests for the ListBasedAddressAuthorizer implementation.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class ListBasedAddressAuthorizerTest extends ModulesTestCase {

    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(
            ListBasedAddressAuthorizerTest.class);

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
                "org.signserver.server.ListBasedAddressAuthorizer");

        // Remove old properties
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "WHITELISTED_DIRECT_ADDRESSES");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_DIRECT_ADDRESSES");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "WHITELISTED_FORWARDED_ADDRESSES");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_FORWARDED_ADDRESSES");

        workerSession.reloadConfiguration(getSignerIdDummy1());
    }


    /**
     * Test that a request coming from an explicitly whitelisted direct address is accepted.
     * 
     * @throws Exception
     */
    public void test01WhitelistedDirectAddressAllowed() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(), "WHITELISTED_DIRECT_ADDRESSES", "127.0.0.1");
        workerSession.setWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_FORWARDED_ADDRESSES", "1.2.3.4");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 200, responseCode);
    }
    
    /**
     * Test that a request coming from an address not in the whitelist is denied.
     * 
     * @throws Exception
     */
    public void test02WhitelistedDirectAddressNotAllowed() throws Exception {
       workerSession.setWorkerProperty(getSignerIdDummy1(), "WHITELISTED_DIRECT_ADDRESSES", "1.2.3.4");
       workerSession.reloadConfiguration(getSignerIdDummy1());
       
       int responseCode = process(
               new URL("http://localhost:" + getPublicHTTPPort()
               + "/signserver/process?workerId="
               + getSignerIdDummy1() + "&data=%3Croot/%3E"));
       
       assertTrue("HTTP response code: " + responseCode,
               responseCode == 401 || responseCode == 403);
    }
    
    /**
     * Test that a request is allowed when the direct whitelist contains more
     * than one address, localhost being one of them.
     * 
     * @throws Exception
     */
    public void test03WhitelistedDirectAddressAllowedSeveral() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(), "WHITELISTED_DIRECT_ADDRESSES",
                "127.0.0.1, 1.2.3.4");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 200, responseCode);        
    }
    
    /**
     * Test that access is denied when setting a forwarded whitelist
     * and no forwarded header is present, even though the direct address
     * is whitelisted.
     * 
     * @throws Exception
     */
    public void test04WhitelistedDirectAddressAndWhitelistedForwarded() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(), "WHITELISTED_FORWARDED_ADDRESSES",
                "42.42.42.42");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_FORWARDED_ADDRESSES");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertTrue("HTTP response code: " + responseCode, 
                responseCode == 401 || responseCode == 403);        
    }
    
    /**
     * Test that access is granted when whitelisting the local address
     * and setting a forwarded address with a forwarding whitelisting.
     * 
     * @throws Exception
     */
    public void test05WhitelistedDirectWithForwarding() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(), "WHITELISTED_DIRECT_ADDRESSES", "127.0.0.1");
        workerSession.setWorkerProperty(getSignerIdDummy1(), "WHITELISTED_FORWARDED_ADDRESSES", "1.2.3.4");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_FORWARDED_ADDRESSES");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "1.2.3.4");
        assertEquals("HTTP response code", 200, responseCode);
    }
    
    /**
     * Test that access is denied when direct address is whitelisted, but forwarding is used
     * and the forwarded address is not in the forwarding whitelist.
     * 
     * @throws Exception
     */
    public void test06WhitelistedDirectWithForwadingNotInWhitelist() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(), "WHITELISTED_FORWARDED_ADDRESSES", "42.42.42.42");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "1.2.3.4");
        assertTrue("HTTP response code: " + responseCode, 
                responseCode == 401 || responseCode == 403);
    }
    
    /**
     * Test that access is denied when the forwading whitelist contains an adress
     * and that address is not the last address in the X-Forwarded-For header
     * (we should only consider that last proxy in case there is a proxy chain).
     * 
     * @throws Exception
     */
    public void test07WhitelistedDirectWithForwardingNotLastAddress() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(), "WHITELISTED_FORWARDED_ADDRESSES", "1.2.3.4");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "1.2.3.4, 42.42.42");
        assertTrue("HTTP response code: " + responseCode, 
                responseCode == 401 || responseCode == 403); 
    }
    
    /**
     * Test that access is denied when blacklisting the forwarded address
     * although the direct address is whitelisted.
     * 
     * @throws Exception
     */
    public void test08WhitelistedDirectWithBlacklistedForwarded() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_FORWARDED_ADDRESSES", "1.2.3.4");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "WHITELISTED_FORWARDED_ADDRESSES");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "1.2.3.4");
        assertTrue("HTTP response code: " + responseCode, 
                responseCode == 401 || responseCode == 403); 
    }
    
    /**
     * Test that access is denied when the direct address is denied.
     * 
     * @throws Exception
     */
    public void test09BlacklistedDirect() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_DIRECT_ADDRESSES", "127.0.0.1");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "WHITELISTED_DIRECT_ADDRESSES");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertTrue("HTTP response code: " + responseCode, 
                responseCode == 401 || responseCode == 403);
    }
    
    /**
     * Test that access is granted when whitelisting the direct address
     * and having a whitelist for forwarded addresses containing several
     * addresses (including the one used in the request).
     * 
     * @throws Exception
     */
    public void test10WhitelistedDirectWithMultipleWhitelistedForwarded() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(), "WHITELISTED_DIRECT_ADDRESSES", "127.0.0.1");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_DIRECT_ADDRESSES");
        workerSession.setWorkerProperty(getSignerIdDummy1(), "WHITELISTED_FORWARDED_ADDRESSES", 
                "1.2.3.4, 42.42.42.42");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_FORWARDED_ADDRESSES");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "1.2.3.4");
        assertEquals("HTTP response code", 200, responseCode); 
    }
    
    /**
     * Test that setting none of the properties make requests fail
     * with internal server error.
     * 
     * @throws Exception
     */
    public void test11NoPropertiesSet() throws Exception {
       workerSession.removeWorkerProperty(getSignerIdDummy1(), "WHITELISTED_DIRECT_ADDRESSES");
       workerSession.removeWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_DIRECT_ADDRESSES");
       workerSession.removeWorkerProperty(getSignerIdDummy1(), "WHITELISTED_FORWARDED_ADDRESSES");
       workerSession.removeWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_FORWARDED_ADDRESSES");
       workerSession.reloadConfiguration(getSignerIdDummy1());
     
       int responseCode = process(
               new URL("http://localhost:" + getPublicHTTPPort()
               + "/signserver/process?workerId="
               + getSignerIdDummy1() + "&data=%3Croot/%3E"));
       assertEquals("HTTP response code", 500, responseCode);
    }
    
    /**
     * Tests that setting both white- and blacklisting simultaniously for direct
     * addresses makes requests fail with internal server error.
     * 
     * @throws Exception
     */
    public void test12BothDirectAddressPropertiesSet() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(), "WHITELISTED_DIRECT_ADDRESSES", "127.0.0.1");
        workerSession.setWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_DIRECT_ADDRESSES", "127.0.0.1");
        workerSession.setWorkerProperty(getSignerIdDummy1(), "WHITELISTED_FORWARDED_ADDRESSES", "127.0.0.1");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 500, responseCode);
    }
    
    /**
     * Tests that setting both white- and blacklisting simultaniously for forwarded
     * addresses makes requests fail with internal server error.
     * 
     * @throws Exception
     */
    public void test13BothForwardedAddressPropertiesSet() throws Exception {
        workerSession.setWorkerProperty(getSignerIdDummy1(), "WHITELISTED_FORWARDED_ADDRESSES", "127.0.0.1");
        workerSession.setWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_FORWARDED_ADDRESSES", "127.0.0.1");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "WHITELISTED_DIRECT_ADDRESSES");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 500, responseCode);
    }

    /**
     * Tests that not specifying a list for direct address fails.
     * 
     * @throws Exception
     */
    public void test14MissingDirectAddresses() throws Exception {
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "WHITELISTED_FORWARDED_ADDRESSES");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "WHITELISTED_DIRECT_ADDRESSES");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_DIRECT_ADDRESSES");
        workerSession.setWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_FORWARDED_ADDRESSES", "127.0.0.1");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 500, responseCode);
    }
    
    /**
     * Tests that not specifying a list for forwarded addresses fails.
     * 
     * @throws Exception
     */
    public void test15MissingForwardedAddresses() throws Exception {
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "WHITELISTED_FORWARDED_ADDRESSES");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_FORWARDED_ADDRESSES");
        workerSession.removeWorkerProperty(getSignerIdDummy1(), "WHITELISTED_DIRECT_ADDRESSES");
        workerSession.setWorkerProperty(getSignerIdDummy1(), "BLACKLISTED_DIRECT_ADDRESSES", "127.0.0.1");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 500, responseCode);
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
