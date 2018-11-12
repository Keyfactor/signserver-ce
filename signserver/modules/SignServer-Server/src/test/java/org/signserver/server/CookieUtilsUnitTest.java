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

import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Unit tests for the CookieUtils class.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CookieUtilsUnitTest {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CookieUtilsUnitTest.class);

    public CookieUtilsUnitTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of toCookiePair method, of class CookieUtils.
     */
    @Test
    public void testToCookiePair() {
        LOG.info("testToCookiePair");

        // Check some simple values
        assertEquals("key1=value1", CookieUtils.toCookiePair("key1", "value1"));
        assertEquals("cookie2=cookieval2", CookieUtils.toCookiePair("cookie2", "cookieval2"));
        
        // Check equals sign in cookie-octet
        assertEquals("cookie3=%3D", CookieUtils.toCookiePair("cookie3", "="));
        assertEquals("cookie3=%3D%3D", CookieUtils.toCookiePair("cookie3", "=="));
        assertEquals("cookie3=cookieval3%3Dvalue3", CookieUtils.toCookiePair("cookie3", "cookieval3=value3"));
        
        // Check paranthesis in cookie-octet
        assertEquals("cookie4=cookie%28%29", CookieUtils.toCookiePair("cookie4", "cookie()"));
        
        // Check some of the cookie-octets handling (more tests are in testToCookieValue()) to see that this method uses that one
        assertEquals("key4=comma%2C", CookieUtils.toCookiePair("key4", "comma,"));
    }

    /**
     * Test of toCookieName method, of class CookieUtils.
     */
    @Test
    public void testToCookieName() {
        LOG.info("testToCookieName");

        // Check some simple values
        assertEquals("name1", CookieUtils.toCookieName("name1"));
        assertEquals("other", CookieUtils.toCookieName("other"));
        
        // TODO: Check some trickier values
    }

    /**
     * Test of fromCookieName method, of class CookieUtils.
     */
    @Test
    public void testFromCookieName() {
        LOG.info("testFromCookieName");

        // Check some simple values
        assertEquals("name1", CookieUtils.fromCookieName("name1"));
        assertEquals("other", CookieUtils.fromCookieName("other"));
        
    }

    /**
     * Test of toCookieValue method, of class CookieUtils.
     */
    @Test
    public void testToCookieValue() {
        LOG.info("testToCookieValue");
        
        // Check some simple values
        assertEquals("abcABC", CookieUtils.toCookieValue("abcABC"));
     
        // Check with 'whitespace'
        assertEquals("%20", CookieUtils.toCookieValue(" "));
        assertEquals("With%20whitespace", CookieUtils.toCookieValue("With whitespace"));
        assertEquals("With%202%20whitespaces", CookieUtils.toCookieValue("With 2 whitespaces"));
        
        // Check with 'DQUOTE'
        assertEquals("%22", CookieUtils.toCookieValue("\""));
        assertEquals("doublequote%22", CookieUtils.toCookieValue("doublequote\""));
        assertEquals("%22doublequote%22", CookieUtils.toCookieValue("\"doublequote\""));
        
        // Check with 'comma'
        assertEquals("%2C", CookieUtils.toCookieValue(","));
        assertEquals("comma%2C", CookieUtils.toCookieValue("comma,"));
        assertEquals("comma%2C%20and%22%2C%22", CookieUtils.toCookieValue("comma, and\",\""));
        
        // Check with 'semicolon'
        assertEquals("%3B", CookieUtils.toCookieValue(";"));
        assertEquals("semicolon%3B", CookieUtils.toCookieValue("semicolon;"));
        assertEquals("semicolon%3B%20again%3B", CookieUtils.toCookieValue("semicolon; again;"));
        
        // Check with 'backslash'
        assertEquals("%5C", CookieUtils.toCookieValue("\\"));
        assertEquals("%5C%5C", CookieUtils.toCookieValue("\\\\"));
        assertEquals("back%5Cslash%5C", CookieUtils.toCookieValue("back\\slash\\"));
        
        // Check with 'CTLs'
        assertEquals("%7F", CookieUtils.toCookieValue("\u007f"));
        assertEquals("%00", CookieUtils.toCookieValue("\u0000"));
        assertEquals("%10", CookieUtils.toCookieValue("\u0010"));
        assertEquals("%1F", CookieUtils.toCookieValue("\u001f"));
        assertEquals("%1F%10", CookieUtils.toCookieValue("\u001f\u0010"));
        
        // Check all
        assertEquals("All:%20%22%20and%20%2C%20and%20%3B%20and%20%5C%20and%20%1F%20or%20%10.", CookieUtils.toCookieValue("All: \" and , and ; and \\ and \u001f or \u0010."));
    }

    /**
     * Test of fromCookieValue method, of class CookieUtils.
     */
    @Test
    public void testFromCookieValue() {
        LOG.info("testFromCookieValue");
        
        // Check some simple values
        assertEquals("abcABC", CookieUtils.fromCookieValue("abcABC"));
        
        // Also check that characters that don't need encoding still can be decoded if they were
        assertEquals("abcABC", CookieUtils.fromCookieValue("%61%62%63%41%42%43"));
        
        // Check with 'whitespace'
        assertEquals(" ", CookieUtils.fromCookieValue("%20"));
        assertEquals("With whitespace", CookieUtils.fromCookieValue("With%20whitespace"));
        assertEquals("With 2 whitespaces", CookieUtils.fromCookieValue("With%202%20whitespaces"));
        
        // Check with 'DQUOTE'
        assertEquals("\"", CookieUtils.fromCookieValue("%22"));
        assertEquals("doublequote\"", CookieUtils.fromCookieValue("doublequote%22"));
        assertEquals("\"doublequote\"", CookieUtils.fromCookieValue("%22doublequote%22"));
        
        // Check with 'comma'
        assertEquals(",", CookieUtils.fromCookieValue("%2C"));
        assertEquals("comma,", CookieUtils.fromCookieValue("comma%2C"));
        assertEquals("comma, and\",\"", CookieUtils.fromCookieValue("comma%2C%20and%22%2C%22"));
        
        // Check with 'semicolon'
        assertEquals(";", CookieUtils.fromCookieValue("%3B"));
        assertEquals("semicolon;", CookieUtils.fromCookieValue("semicolon%3B"));
        assertEquals("semicolon; again;", CookieUtils.fromCookieValue("semicolon%3B%20again%3B"));
        
        // Check with 'backslash'
        assertEquals("\\", CookieUtils.fromCookieValue("%5C"));
        assertEquals("\\\\", CookieUtils.fromCookieValue("%5C%5C"));
        assertEquals("back\\slash\\", CookieUtils.fromCookieValue("back%5Cslash%5C"));
        
        // Check with 'CTLs'
        assertEquals("\u007f", CookieUtils.fromCookieValue("%7F"));
        assertEquals("\u0000", CookieUtils.fromCookieValue("%00"));
        assertEquals("\u0010", CookieUtils.fromCookieValue("%10"));
        assertEquals("\u001f", CookieUtils.fromCookieValue("%1F"));
        assertEquals("\u001f\u0010", CookieUtils.fromCookieValue("%1f%10"));
        
        // Check all
        assertEquals("All: \" and , and ; and \\ and \u001f or \u0010.", CookieUtils.fromCookieValue("All:%20%22%20and%20%2C%20and%20%3B%20and%20%5C%20and%20%1F%20or%20%10."));
    }
    
}
