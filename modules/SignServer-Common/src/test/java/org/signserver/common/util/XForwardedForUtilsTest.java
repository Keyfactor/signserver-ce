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
package org.signserver.common.util;

import org.signserver.common.RequestContext;

import junit.framework.TestCase;

/**
 * Tests the X-Forwarded-For header utility methods.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class XForwardedForUtilsTest extends TestCase {

    /**
     * Test using a simple X-Forwarded-For header with a single IP address.
     * The basic case when using i.e. an Apache proxy
     * 
     * @throws Exception
     */
    public void test01XForwardedForSingleIP() throws Exception {
        final RequestContext context = new RequestContext();
        
        context.put(RequestContext.X_FORWARDED_FOR, "42.42.42.42");
        
        final String ip = XForwardedForUtils.getXForwardedForIP(context);
        
        assertEquals("Unexpected IP address parsed from response header", "42.42.42.42", ip);
    }
    
    /**
     * Test not including the X-Forwarded-For header
     * 
     * @throws Exception
     */
    public void test02NoXForwardedFor() throws Exception {
        final RequestContext context = new RequestContext();
        final String ip = XForwardedForUtils.getXForwardedForIP(context);
        
        assertEquals("Should return null when X-Forwarded-For is not set", null, ip);
    }
    
    /**
     * Test setting X-Forwarded-For being empty
     * 
     * @throws Exception
     */
    public void test03EmptyXForwardedFor() throws Exception {
        final RequestContext context = new RequestContext();
        
        context.put(RequestContext.X_FORWARDED_FOR, "");
        
        final String ip = XForwardedForUtils.getXForwardedForIP(context);
        
        assertEquals("Should return null when X-Forwarded-For is empty", null, ip);
    }
    
    /**
     * Test setting X-Forwarded-For to a list of IP addresses
     * 
     * @throws Exception
     */
    public void test04SeveralXForwardedFor() throws Exception {
        final RequestContext context = new RequestContext();
        
        context.put(RequestContext.X_FORWARDED_FOR, "42.42.42.42, 1.2.3.4");
        
        final String ip = XForwardedForUtils.getXForwardedForIP(context);
        
        assertEquals("Should return the last IP address in the X-Forwarded-For header", "1.2.3.4", ip);
    }
    
    /**
     * Test that fetching 2 forwarded addresses gets the last two and that exactly two addresses
     * are returned.
     * 
     * @throws Exception
     */
    public void test05ReturnTwo() throws Exception {
        final RequestContext context = new RequestContext();
        
        context.put(RequestContext.X_FORWARDED_FOR, "42.42.42.42, 1.2.3.4, 47.47.47.47");
        
        final String[] ips = XForwardedForUtils.getXForwardedForIPs(context, 2);
        
        assertEquals("Should return 2 IP addresses", 2, ips.length);
        assertEquals("First element should be last proxied address", "47.47.47.47", ips[0]);
        assertEquals("Second element should be second last proxied address", "1.2.3.4", ips[1]);
    }
    
    /**
     * Test that requesting more addresses that are in the request context works as expected,
     * returning all of them, and don't cause crashes like ArrayIndexOutOfBounds, f.ex.
     * 
     * @throws Exception
     */
    public void test06ShorterList() throws Exception {
        final RequestContext context = new RequestContext();
        
        context.put(RequestContext.X_FORWARDED_FOR, "42.42.42.42, 1.2.3.4, 47.47.47.47");
        
        final String[] ips = XForwardedForUtils.getXForwardedForIPs(context, 5);
        
        assertEquals("Should return all addresses", 3, ips.length);
    }
    
    /**
     * Test that requesting multiple IP addresses with an empty request property
     * gives an empty array.
     * 
     * @throws Exception
     */
    public void test07EmptyList() throws Exception {
        final RequestContext context = new RequestContext();
        
        context.put(RequestContext.X_FORWARDED_FOR, "");
        
        final String[] ips = XForwardedForUtils.getXForwardedForIPs(context, 5);
        
        assertEquals("Should return empty array", 0, ips.length);
    }
    
    /**
     * Test that requesting multiple IP addresses with no header returns null.
     * 
     * @throws Exception
     */
    public void test08NoList() throws Exception {
        final RequestContext context = new RequestContext();
        final String[] ips = XForwardedForUtils.getXForwardedForIPs(context, 5);
        
        assertNull("Should return null", ips);
    }
    
    /**
     * Test that setting the header to an empty list with some extra whitespace
     * still gives an empty array of addresses.
     * 
     * @throws Exception
     */
    public void test09EmptyListExtraWhitespace() throws Exception {
        final RequestContext context = new RequestContext();
        
        context.put(RequestContext.X_FORWARDED_FOR, " ");
        
        final String[] ips = XForwardedForUtils.getXForwardedForIPs(context, 5);
        
        assertEquals("Should return empty array", 0, ips.length);
    }
}
