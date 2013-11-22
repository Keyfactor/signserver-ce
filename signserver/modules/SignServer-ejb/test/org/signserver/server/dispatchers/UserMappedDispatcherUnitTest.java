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
package org.signserver.server.dispatchers;

import org.apache.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;
import org.signserver.common.WorkerConfig;
import org.signserver.server.SignServerContext;
import org.signserver.server.WorkerContext;

/**
 * Unit tests for the UserMappedDispatcher class.
 * 
 * System tests are in the system tests module.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class UserMappedDispatcherUnitTest {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(UserMappedDispatcherUnitTest.class);
    
    /**
     * Tests that not setting the required property gives an error.
     */
    @Test
    public void testMissingProperty() throws Exception {
        LOG.info("testMissingProperty");
        
        // Without property
        WorkerConfig config = new WorkerConfig();
        WorkerContext context = new SignServerContext(null, null);
        UserMappedDispatcher instance = new UserMappedDispatcher();
        instance.init(1, config, context, null);
        assertTrue("errs: " + instance.getFatalErrors(), instance.getFatalErrors().toString().contains("USERNAME_MAPPING"));
        
        // With property
        instance = new UserMappedDispatcher();
        config.setProperty("USERNAME_MAPPING", "user1:worker1, user2:worker2");
        instance.init(2, config, context, null);
        assertTrue("errs: " + instance.getFatalErrors(), instance.getFatalErrors().isEmpty());
    }
    
    /**
     * Tests that having a syntax error in the property value gives an error.
     * @throws Exception 
     */
    @Test
    public void testPropertySyntaxError() throws Exception {
        LOG.info("testPropertySyntaxError");

        WorkerConfig config = new WorkerConfig();
        WorkerContext context = new SignServerContext(null, null);
        UserMappedDispatcher instance = new UserMappedDispatcher();
        config.setProperty("USERNAME_MAPPING", "user1::worker1");
        instance.init(3, config, context, null);
        assertTrue("errs: " + instance.getFatalErrors(), instance.getFatalErrors().toString().contains("USERNAME_MAPPING"));
        
        // Test some border cases without error
        instance = new UserMappedDispatcher();
        config.setProperty("USERNAME_MAPPING", "user1:worker1,\nuser2:worker2");
        instance.init(4, config, context, null);
        assertTrue("new line: " + instance.getFatalErrors(), instance.getFatalErrors().isEmpty());
        
        instance = new UserMappedDispatcher();
        config.setProperty("USERNAME_MAPPING", "");
        instance.init(5, config, context, null);
        assertTrue("empty: " + instance.getFatalErrors(), instance.getFatalErrors().isEmpty());
    }
    
}
