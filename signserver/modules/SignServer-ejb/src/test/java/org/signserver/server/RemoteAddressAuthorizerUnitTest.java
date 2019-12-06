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

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import org.junit.Test;

/**
 * Unit tests for the RemoteAddressAuthorizer class.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class RemoteAddressAuthorizerUnitTest {

    /**
     * Test that allowing literal localhost in IPv6 short-form is allowed when using short-form.
     * 
     * @throws Exception
     */
    @Test
    public void test01RequestIPv6Localhost() throws Exception {
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
    public void test02RequestIPv6LocalhostLongForm() throws Exception {
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
    public void test03RequestIPv6LocalhostShortForm() throws Exception {
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
    public void test04RequestIPv6Accepted() throws Exception {
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
    public void test05RequestIPv6NotAccepted() throws Exception {
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
    public void test06RequestIPv6AcceptedWithIPv4() throws Exception {
        final RemoteAddressAuthorizer auth = new RemoteAddressAuthorizer();
        
        auth.setAllowFromProperty("127.0.0.1, 3ffe:1900:4545:3:200:f8ff:fe21:67cf");
        assertTrue("Allow IPv6 address", auth.isAddressAuthorized("3ffe:1900:4545:3:200:f8ff:fe21:67cf"));
    }
}
