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
package org.signserver.ejb;

import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.InitialContext;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.IStatusRepositorySession;

/**
 * Tests for the StatusRepositorySessionBean.
 *
 * @author Markus Kil�s
 * $Id$
 */
public class StatusRepositorySessionBeanTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG =
            Logger.getLogger(StatusRepositorySessionBeanTest.class);

    /** Property key. */
    private static final String PROPERTY1 = "_TEST_PROPERTY_1";
    
    /** Property key. */
    private static final String PROPERTY2 = "_TEST_PROPERTY_2";
    
    /** Property key. */
    private static final String PROPERTY3 = "_TEST_PROPERTY_3";

    /** Property value. */
    private static final String VALUE1 = "_TEST_VALUE_1";

    /** Property value. */
    private static final String VALUE2 = "_TEST_VALUE_2";

    /** Property value. */
    private static final String VALUE3 = "_TEST_VALUE_3";

    /** Waittime in ms for testing expiration. */
    private static final long TIMEOUT = 100;

    /** The status repository session. */
    private IStatusRepositorySession.IRemote repository;

    
    @Override
    protected void setUp() throws Exception {
        repository = ServiceLocator.getInstance().lookupRemote(
                    IStatusRepositorySession.IRemote.class);
    }

    @Override
    protected void tearDown() throws Exception {
        repository.removeProperty(PROPERTY1);
        repository.removeProperty(PROPERTY2);
        repository.removeProperty(PROPERTY3);
    }

    /**
     * Tests to set 2 values, reading them and then removing them.
     * 
     * @throws Exception in case of exception
     */
    public void testSetGetRemoveProperty() throws Exception {

        // Set properties
        repository.setProperty(PROPERTY1, VALUE1);
        repository.setProperty(PROPERTY2, VALUE2);

        // Read the properties
        final String value1 = repository.getProperty(PROPERTY1);
        assertEquals("Property 1", VALUE1, value1);
        final String value2 = repository.getProperty(PROPERTY2);
        assertEquals("Property 2", VALUE2, value2);

        // Remove the properties
        repository.removeProperty(PROPERTY1);
        repository.removeProperty(PROPERTY2);

        // Should return null now
        final String value3 = repository.getProperty(PROPERTY1);
        assertNull("Property 1 null", value3);
        final String value4 = repository.getProperty(PROPERTY2);
        assertNull("Property 2 null", value4);
    }

    /**
     * Tests setting a value with a timeout and reading it both before and
     * after a time.
     * @throws Exception in case of exception
     */
    public void testSetGetTimeout() throws Exception {
        final long expiration = System.currentTimeMillis() + TIMEOUT;
        repository.setProperty(PROPERTY3, VALUE3, expiration);

        // Get the value right away
        final String value1 = repository.getProperty(PROPERTY3);
        assertEquals("getProperty right away", VALUE3, value1);

        // Wait a time (twice the TIMEOUT to be sure)
        try {
            Thread.sleep(2 * TIMEOUT);
        } catch (InterruptedException ex) {
            LOG.error("Sleep was interrupted, the next test might fail.", ex);
        }

        // Now the value should have expired
        final String value2 = repository.getProperty(PROPERTY3);
        assertNull("getProperty expired", value2);
    }

}
