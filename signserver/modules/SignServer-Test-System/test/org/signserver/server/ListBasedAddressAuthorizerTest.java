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
import java.util.List;

import org.apache.log4j.Logger;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerStatus;
import org.signserver.testutils.ModulesTestCase;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for the ListBasedAddressAuthorizer implementation.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ListBasedAddressAuthorizerTest extends ModulesTestCase {

    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(
            ListBasedAddressAuthorizerTest.class);

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        LOG.info(">test00SetupDatabase");
        addDummySigner1();

        // Set auth type
        workerSession.setWorkerProperty(getSignerIdDummy1(), "AUTHTYPE",
                "org.signserver.server.ListBasedAddressAuthorizer");

        // Remove old properties
        setPropertiesAndReload(null, null, null, null);
    }


    /**
     * Test that a request coming from an explicitly whitelisted direct address is accepted.
     * 
     * @throws Exception
     */
    @Test
    public void test01WhitelistedDirectAddressAllowed() throws Exception {
        LOG.info(">test01WhitelistedDirectAddressAllowed");
        setPropertiesAndReload("127.0.0.1", null, null, "1.2.3.4");
        
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
    @Test
    public void test02WhitelistedDirectAddressNotAllowed() throws Exception {
       LOG.info(">test02WhitelistedDirectAddressNotAllowed");
       setPropertiesAndReload(null, null, null, null);
       setPropertiesAndReload("1.2.3.4", null, null, "1.2.3.4");
       
       int responseCode = process(
               new URL("http://localhost:" + getPublicHTTPPort()
               + "/signserver/process?workerId="
               + getSignerIdDummy1() + "&data=%3Croot/%3E"));
       
       assertEquals("HTTP response code", 403, responseCode);
    }
    
    /**
     * Test that a request is allowed when the direct whitelist contains more
     * than one address, localhost being one of them.
     * 
     * @throws Exception
     */
    @Test
    public void test03WhitelistedDirectAddressAllowedSeveral() throws Exception {
        LOG.info(">test03WhitelistedDirectAddressAllowedSeveral");
        setPropertiesAndReload("127.0.0.1, 1.2.3.4", null, null, "1.2.3.4");
      
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
    @Test
    public void test04WhitelistedDirectAddressAndWhitelistedForwarded() throws Exception {
        LOG.info(">test04WhitelistedDirectAddressAndWhitelistedForwarded");
        setPropertiesAndReload("127.0.0.1", null, "42.42.42.42", null);
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 403, responseCode);        
    }
    
    /**
     * Test that access is granted when whitelisting the local address
     * and setting a forwarded address with a forwarding whitelisting.
     * 
     * @throws Exception
     */
    @Test
    public void test05WhitelistedDirectWithForwarding() throws Exception {
        LOG.info(">test05WhitelistedDirectWithForwarding");
        setPropertiesAndReload("127.0.0.1", null, "1.2.3.4", null);
       
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
    @Test
    public void test06WhitelistedDirectWithForwadingNotInWhitelist() throws Exception {
        LOG.info(">test06WhitelistedDirectWithForwadingNotInWhitelist");
        setPropertiesAndReload("127.0.0.1", null, "42.42.42.42", null);

        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "1.2.3.4");
        assertEquals("HTTP response code", 403, responseCode);
    }
    
    /**
     * Test that access is denied when the forwarding whitelist contains an address
     * and that address is not the last address in the X-Forwarded-For header
     * (we should only consider that last proxy in case there is a proxy chain).
     * 
     * @throws Exception
     */
    @Test
    public void test07WhitelistedDirectWithForwardingNotLastAddress() throws Exception {
        LOG.info(">test07WhitelistedDirectWithForwardingNotLastAddress");
        setPropertiesAndReload("127.0.0.1", null, "1.2.3.4", null);

        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "1.2.3.4, 42.42.42.42");
        assertEquals("HTTP response code", 403, responseCode); 
    }
    
    /**
     * Test that access is denied when blacklisting the forwarded address
     * although the direct address is whitelisted.
     * 
     * @throws Exception
     */
    @Test
    public void test08WhitelistedDirectWithBlacklistedForwarded() throws Exception {
        LOG.info(">test08WhitelistedDirectWithBlacklistedForwarded");
        setPropertiesAndReload("127.0.0.1", null, null, "1.2.3.4");
      
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "1.2.3.4");
        assertEquals("HTTP response code", 403, responseCode); 
    }
    
    /**
     * Test that access is denied when the direct address is denied.
     * 
     * @throws Exception
     */
    @Test
    public void test09BlacklistedDirect() throws Exception {
        LOG.info(">test09BlacklistedDirect");
        setPropertiesAndReload(null, "127.0.0.1", null, "1.2.3.4");

        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 403, responseCode);
    }
    
    /**
     * Test that access is granted when whitelisting the direct address
     * and having a whitelist for forwarded addresses containing several
     * addresses (including the one used in the request).
     * 
     * @throws Exception
     */
    @Test
    public void test10WhitelistedDirectWithMultipleWhitelistedForwarded() throws Exception {
        LOG.info(">test10WhitelistedDirectWithMultipleWhitelistedForwarded");
        setPropertiesAndReload("127.0.0.1", null, "1.2.3.4, 127.0.0.1", null);
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "1.2.3.4");
        assertEquals("HTTP response code", 200, responseCode); 
    }
    
    /**
     * Test that setting none of the properties generates the correct fatal error.
     * 
     * @throws Exception
     */
    @Test
    public void test11NoPropertiesSet() throws Exception {
       LOG.info(">test11NoPropertiesSet");
       setPropertiesAndReload(null, null, null, null);
    
       int responseCode = process(
               new URL("http://localhost:" + getPublicHTTPPort()
               + "/signserver/process?workerId="
               + getSignerIdDummy1() + "&data=%3Croot/%3E"));
       assertEquals("HTTP response code", 500, responseCode);
    }
    
    /**
     * Tests that setting both white- and blacklisting simultaniously for direct
     * addresses generates correct fatal error.
     * 
     * @throws Exception
     */
    @Test
    public void test12BothDirectAddressPropertiesSet() throws Exception {
        LOG.info(">test12BothDirectAddressPropertiesSet");
        setPropertiesAndReload("127.0.0.1", "127.0.0.1", "127.0.0.1", null);
       
        final WorkerStatus status = workerSession.getStatus(getSignerIdDummy1());
        final List<String> fatalErrors = status.getFatalErrors();
        
        assertTrue("Contains fatal error",
                fatalErrors.contains("Only one of WHITELISTED_DIRECT_ADDRESSES and BLACKLISTED_DIRECT_ADDRESSES can be specified."));
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 500, responseCode);
    }
    
    /**
     * Tests that setting both white- and blacklisting simultaniously for forwarded
     * addresses generates correct fatal error.
     * 
     * @throws Exception
     */
    @Test
    public void test13BothForwardedAddressPropertiesSet() throws Exception {
        LOG.info(">test13BothForwardedAddressPropertiesSet");
        setPropertiesAndReload(null, "127.0.0.1", "127.0.0.1", "127.0.0.1");
        
        final WorkerStatus status = workerSession.getStatus(getSignerIdDummy1());
        final List<String> fatalErrors = status.getFatalErrors();
        
        assertTrue("Contains fatal error",
                fatalErrors.contains("Only one of WHITELISTED_FORWARDED_ADDRESSES and BLACKLISTED_FORWARDED_ADDRESSES can be specified."));
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 500, responseCode);
    }

    /**
     * Tests that not specifying a list for direct address generates the correct fatal error.
     * 
     * @throws Exception
     */
    @Test
    public void test14MissingDirectAddresses() throws Exception {
        LOG.info(">test14MissingDirectAddresses");
        setPropertiesAndReload(null, null, null, "127.0.0.1");
       
        final WorkerStatus status = workerSession.getStatus(getSignerIdDummy1());
        final List<String> fatalErrors = status.getFatalErrors();
        
        assertTrue("Contains fatal error",
                fatalErrors.contains("One of WHITELISTED_DIRECT_ADDRESSES or BLACKLISTED_DIRECT_ADDRESSES must be specified."));
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 500, responseCode);
    }
    
    /**
     * Tests that not specifying a list for forwarded addresses generates the correct fatal error.
     * 
     * @throws Exception
     */
    @Test
    public void test15MissingForwardedAddresses() throws Exception {
        LOG.info(">test15MissingForwardedAddresses");
        setPropertiesAndReload(null, "127.0.0.1", null, null);
       
        final WorkerStatus status = workerSession.getStatus(getSignerIdDummy1());
        final List<String> fatalErrors = status.getFatalErrors();
        
        assertTrue("Contains fatal error",
                fatalErrors.contains("One of WHITELISTED_FORWARDED_ADDRESSES or BLACKLISTED_FORWARDED_ADDRESSES must be specified."));
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 500, responseCode);
    }
    
    /**
     * Tests that specifying a whitelisted forwarded IPv6 address and using the
     * exact same form in the request works.
     * 
     * @throws Exception
     */
    @Test
    public void test16ForwardedIPv6SameForm() throws Exception {
       LOG.info(">test16ForwardedIPv6SameForm");
       setPropertiesAndReload("127.0.0.1", null, "3ffe:1900:4545:3:200:f8ff:fe21:67cf", null);
       
       int responseCode = process(
               new URL("http://localhost:" + getPublicHTTPPort()
               + "/signserver/process?workerId="
               + getSignerIdDummy1() + "&data=%3Croot/%3E"), "3ffe:1900:4545:3:200:f8ff:fe21:67cf");
       assertEquals("HTTP response code", 200, responseCode);
    }
    
    /**
     * Test that setting a forwarded whitelisted shortened IPv6 address and using
     * the full form in the request works.
     * 
     * @throws Exception
     */
    @Test
    public void test17ForwardedIPv6LocalhostLongForm() throws Exception {
       LOG.info(">test17ForwardedIPv6LocalhostLongForm");
       setPropertiesAndReload("127.0.0.1", null, "::1", null);
       
       int responseCode = process(
               new URL("http://localhost:" + getPublicHTTPPort()
               + "/signserver/process?workerId="
               + getSignerIdDummy1() + "&data=%3Croot/%3E"), "0000:0000:0000:0000:0000:0000:0000:0001");
       assertEquals("HTTP response code", 200, responseCode);
    }
    
    /**
     * Test that a request from a non-whitelisted forwarded IPv6 address is rejected.
     * 
     * @throws Exception
     */
    @Test
    public void test18ForwardedNotAllowedIPv6() throws Exception {
        LOG.info(">test18ForwardedNotAllowedIPv6");
        setPropertiesAndReload("127.0.0.1", null, "::1", null);
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "3ffe:1900:4545:3:200:f8ff:fe21:67cf");
        assertEquals("HTTP response code", 403, responseCode);
    }
    
    /**
     * Test that a blacklisted forwarded IPv6 address is rejected.
     * 
     * @throws Exception
     */
    @Test
    public void test19ForwardedBlacklistedIPv6() throws Exception {
        LOG.info(">test19ForwardedBlacklistedIPv6");
        setPropertiesAndReload("127.0.0.1", null, null, "3ffe:1900:4545:3:200:f8ff:fe21:67cf");
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "3ffe:1900:4545:3:200:f8ff:fe21:67cf");
        assertEquals("HTTP response code", 403, responseCode);
    }
    
    
    /**
     * Test that blacklisting forwarded localhost addresses using the shortened form
     * also blocks requests using the full form.
     * 
     * @throws Exception
     */
    @Test
    public void test20ForwardedBlackListedIPv6LocalhostLongForm() throws Exception {
        LOG.info(">test20ForwardedBlackListedIPv6LocalhostLongForm");
        setPropertiesAndReload("127.0.0.1", null, null, "::1");
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "0000:0000:0000:0000:0000:0000:0000:0001");
        assertEquals("HTTP response code", 403, responseCode);
    }
    
    /**
     * Test that blacklisting forwarded localhost addresses using the full form
     * also blocks requests using the shortened form.
     * 
     * @throws Exception
     */
    @Test
    public void test21ForwardedBlacklistedIPv6LocalhostShortForm() throws Exception {
        LOG.info(">test21ForwardedBlacklistedIPv6LocalhostShortForm");
        setPropertiesAndReload("127.0.0.1", null, null, "0000:0000:0000:0000:0000:0000:0000:0001");
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "::1");
        assertEquals("HTTP response code", 403, responseCode);
    }

    /**
     * Test that the default is checking only the last IP address for whitelisting.
     * 
     * @throws Exception
     */
    @Test
    public void test22ForwardedWhitelistDefaultMax() throws Exception {
        LOG.info(">test22ForwardedWhitelistDefaultMax");
        setPropertiesAndReload("127.0.0.1", null, "1.2.3.4", null);
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "1.2.3.4, 42.42.42.42");
        assertEquals("HTTP response code", 403, responseCode);
    }
    
    /**
     * Test that checking two proxy addresses works as expected.
     * 
     * @throws Exception
     */
    @Test
    public void test23ForwardedWhitelistTwoProxies() throws Exception {
        LOG.info(">test23ForwardedWhitelistTwoProxies");
        setPropertiesAndReload("127.0.0.1", null, "1.2.3.4, 42.42.42.42", null);
        workerSession.setWorkerProperty(getSignerIdDummy1(), "MAX_FORWARDED_ADDRESSES", "2");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "1.2.3.4, 42.42.42.42");
        assertEquals("HTTP response code", 200, responseCode);
    }
    
    /**
     * Test that adding an extra address to the header, past the number of trusted proxies
     * is not allowed.
     * 
     * @throws Exception
     */
    @Test
    public void test24ForwardedWhitelistTwoProxiesAddionalHeader() throws Exception {
        LOG.info(">test24ForwardedWhitelistTwoProxiesAddionalHeader");
        setPropertiesAndReload("127.0.0.1", null, "1.2.3.4", null);
        workerSession.setWorkerProperty(getSignerIdDummy1(), "MAX_FORWARDED_ADDRESSES", "2");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"), "1.2.3.4, 42.42.42.42, 5.6.7.8");
        assertEquals("HTTP response code", 403, responseCode);
    }
    
    /**
     * Test that blacklisting with maximum one checked address won't
     * block an adress when it's not the last in the header.
     * 
     * @throws Exception
     */
    @Test
    public void test25ForwardedBlacklistTwoProxiesOneCheck() throws Exception {
        LOG.info(">test25ForwardedBlacklistTwoProxiesOneCheck");
        setPropertiesAndReload("127.0.0.1", null, null, "1.2.3.4");
        workerSession.setWorkerProperty(getSignerIdDummy1(), "MAX_FORWARDED_ADDRESSES", "1");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"),
                "1.2.3.4, 42.42.42.42, 5.6.7.8");
        assertEquals("HTTP response code", 200, responseCode);
    }
    
    /**
     * Test that granting access to two forwarded addresses, checking two addresses with a header containing
     * three entries with one of the last two (the checked ones) being not in the authorized list results in
     * non-access.
     * 
     * @throws Exception
     */
    @Test
    public void test26ForwardedWhitelistThreeProxiesTwoCheckedOneUnauthorized() throws Exception {
        LOG.info(">test26ForwardedWhitelistThreeProxiesTwoCheckedOneUnauthorized");
        setPropertiesAndReload("127.0.0.1", null, "1.2.3.4, 42.42.42.42", null);
        workerSession.setWorkerProperty(getSignerIdDummy1(), "MAX_FORWARDED_ADDRESSES", "2");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"),
                "47.47.47.47, 5.6.7.8, 1.2.3.4");
        assertEquals("HTTP response code", 403, responseCode);
    }
    
    /**
     * Test that setting MAX_FORWARDED_ADDRESSES to 0 will result in a fatal error, for security reasons
     * 
     * @throws Exception
     */
    @Test
    public void test27Max0NotAllowed() throws Exception {
        LOG.info(">test27Max0NotAllowed");
        setPropertiesAndReload("127.0.0.1", null, "1.2.3.4, 42.42.42.42", null);
        workerSession.setWorkerProperty(getSignerIdDummy1(), "MAX_FORWARDED_ADDRESSES", "0");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        final WorkerStatus status = workerSession.getStatus(getSignerIdDummy1());
        final List<String> fatalErrors = status.getFatalErrors();
        
        assertTrue("Contains fatal error",
                fatalErrors.contains("Illegal value for MAX_FORWARDED_ADDRESSES: 0"));
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 500, responseCode);
    }
    
    /**
     * Test that setting MAX_FORWARDED_ADDRESSES to a negative value is not allowed.
     * 
     * @throws Exception
     */
    @Test
    public void test28NegativeMaxNotAllowed() throws Exception {
        LOG.info(">test28NegativeMaxNotAllowed");
        setPropertiesAndReload("127.0.0.1", null, "1.2.3.4, 42.42.42.42", null);
        workerSession.setWorkerProperty(getSignerIdDummy1(), "MAX_FORWARDED_ADDRESSES", "-2");
        workerSession.reloadConfiguration(getSignerIdDummy1());
        
        final WorkerStatus status = workerSession.getStatus(getSignerIdDummy1());
        final List<String> fatalErrors = status.getFatalErrors();
        
        assertTrue("Contains fatal error",
                fatalErrors.contains("Illegal value for MAX_FORWARDED_ADDRESSES: -2"));
        
        int responseCode = process(
                new URL("http://localhost:" + getPublicHTTPPort()
                + "/signserver/process?workerId="
                + getSignerIdDummy1() + "&data=%3Croot/%3E"));
        assertEquals("HTTP response code", 500, responseCode);
    }
    
    /**
     * Test that setting MAX_FORWARDED_ADDRESSES to some bogus non-numerical value is not allowed.
     * @throws Exception
     */
    @Test
    public void test29BogusMax() throws Exception {
        LOG.info(">test29BogusMax");
        try {
            setPropertiesAndReload("127.0.0.1", null, "1.2.3.4, 42.42.42.42", null);
            workerSession.setWorkerProperty(getSignerIdDummy1(), "MAX_FORWARDED_ADDRESSES", "foo123");
            workerSession.reloadConfiguration(getSignerIdDummy1());

            final WorkerStatus status = workerSession.getStatus(getSignerIdDummy1());
            final List<String> fatalErrors = status.getFatalErrors();

            assertTrue("Contains fatal error",
                    fatalErrors.contains("Illegal value for MAX_FORWARDED_ADDRESSES: foo123"));

            int responseCode = process(
                    new URL("http://localhost:" + getPublicHTTPPort()
                    + "/signserver/process?workerId="
                    + getSignerIdDummy1() + "&data=%3Croot/%3E"));
            assertEquals("HTTP response code", 500, responseCode);
        } finally {
            workerSession.removeWorkerProperty(getSignerIdDummy1(), "MAX_FORWARDED_ADDRESSES");
            workerSession.reloadConfiguration(getSignerIdDummy1());
        }
    }
    
    /**
     * Utility method to set the access list properties (null removes a property)
     */
    private void setPropertiesAndReload(final String whitelistedDirect, final String blacklistedDirect,
            final String whitelistedForwarded, final String blacklistedForwarded) {
        setOrRemoveProperty("WHITELISTED_DIRECT_ADDRESSES", whitelistedDirect);
        setOrRemoveProperty("BLACKLISTED_DIRECT_ADDRESSES", blacklistedDirect);
        setOrRemoveProperty("WHITELISTED_FORWARDED_ADDRESSES", whitelistedForwarded);
        setOrRemoveProperty("BLACKLISTED_FORWARDED_ADDRESSES", blacklistedForwarded);
        workerSession.reloadConfiguration(getSignerIdDummy1());
    }
        
    private void setOrRemoveProperty(final String property, final String value) {
        if (value == null) {
            workerSession.removeWorkerProperty(getSignerIdDummy1(), property);
        } else {
            workerSession.setWorkerProperty(getSignerIdDummy1(), property, value);
        }
    }
    
    private int process(URL workerUrl, final String forwardIPs) {
        int responseCode = -1;

        HttpURLConnection conn;
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

    @Test
    public void test99TearDownDatabase() throws Exception {
        LOG.info(">test99TearDownDatabase");
        removeWorker(getSignerIdDummy1());
        workerSession.reloadConfiguration(getSignerIdDummy1());
    }
}
