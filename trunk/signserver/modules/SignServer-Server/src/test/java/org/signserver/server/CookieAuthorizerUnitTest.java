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

import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.WorkerConfig;

/**
 * Unit tests for CookieAutorizer feature.
 * 
 * @author George Matveev
 * @version $Id$
 */
public class CookieAuthorizerUnitTest {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(CookieAuthorizerUnitTest.class);
    
    public CookieAuthorizerUnitTest() {
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
     * Test of REQUEST_COOKIES_PREFIX property, of class CookieAuthorizer.
     * @throws java.lang.Exception
     */
    @Test
    public void testInit() throws Exception {
        LOG.info("testInit");
        int workerId = 0;
        WorkerConfig config = new WorkerConfig();
        final String cookiePrefix = "REQUEST_COOKIES_PREFIX";
        
        EntityManager em = null;
        CookieAuthorizer instance = new CookieAuthorizer();
        instance.init(workerId, config, em);
        //get Cookie prefix from XAdESSigner worker configuration but it is NOT set
        String fatalErrors = instance.getFatalErrors().toString();
        assertTrue("fatalErrors: " + fatalErrors, fatalErrors.contains(cookiePrefix));
        
        //NOW we SET REQUEST_COOKIES_PREFIX property to AIRLOCK
        config.setProperty(cookiePrefix, "AIRLOCK");
        
        instance = new CookieAuthorizer();
        instance.init(workerId, config, em);
        fatalErrors = instance.getFatalErrors().toString();
        assertFalse("fatalErrors: " + fatalErrors, fatalErrors.contains(cookiePrefix));
    }    
}
