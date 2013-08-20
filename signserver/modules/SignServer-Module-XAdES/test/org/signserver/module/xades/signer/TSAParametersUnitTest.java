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
package org.signserver.module.xades.signer;

import org.apache.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for the TSAParameters class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TSAParametersUnitTest {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TSAParametersUnitTest.class);

    /**
     * Test of getUrl method, of class TSAParameters.
     */
    @Test
    public void testGetUrl() {
        LOG.info("getUrl");
        TSAParameters instance = new TSAParameters("http://example.com/?test=1");
        String expResult = "http://example.com/?test=1";
        String result = instance.getUrl();
        assertEquals("ctor1", expResult, result);
        
        instance = new TSAParameters("http://example.com/?test=2", null, null);
        expResult = "http://example.com/?test=2";
        result = instance.getUrl();
        assertEquals("ctor2", expResult, result);
    }

    /**
     * Test of getUsername method, of class TSAParameters.
     */
    @Test
    public void testGetUsername() {
        LOG.info("getUsername");
        TSAParameters instance = new TSAParameters("http://example.com/?test=123");
        assertNull("ctor1", instance.getUsername());
        
        instance = new TSAParameters("http://example.com/?test=123", "username", "");
        String expResult = "username";
        String result = instance.getUsername();
        assertEquals(expResult, result);
    }

    /**
     * Test of getPassword method, of class TSAParameters.
     */
    @Test
    public void testGetPassword() {
        LOG.info("getPassword");
        TSAParameters instance = new TSAParameters("http://example.com/?test=123");
        assertNull("ctor1", instance.getPassword());
        
        instance = new TSAParameters("http://example.com/?test=123", "username", "password");
        String expResult = "password";
        String result = instance.getPassword();
        assertEquals(expResult, result);
    }
}
