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

import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.signserver.common.ServiceLocator;
import org.signserver.statusrepo.IStatusRepositorySession;
import org.signserver.statusrepo.common.StatusEntry;
import org.signserver.statusrepo.common.StatusName;

/**
 * Tests for the StatusRepositorySessionBean.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class StatusRepositorySessionBeanTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG =
            Logger.getLogger(StatusRepositorySessionBeanTest.class);

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
        repository.update(StatusName.TEST_PROPERTY1.name(), null);
        repository.update(StatusName.TEST_PROPERTY2.name(), null);
        repository.update(StatusName.TEST_PROPERTY3.name(), null);
    }

    /**
     * Tests to set 2 values, reading them and then removing them.
     * 
     * @throws Exception in case of exception
     */
    public void testSetGetRemoveProperty() throws Exception {

        // Set properties
        repository.update(StatusName.TEST_PROPERTY1.name(), VALUE1);
        repository.update(StatusName.TEST_PROPERTY2.name(), VALUE2);

        // Read the properties
        final StatusEntry entry1 = repository.getValidEntry(StatusName.TEST_PROPERTY1.name());
        assertEquals("Property 1", VALUE1, entry1.getValue());
        final StatusEntry entry2 = repository.getValidEntry(StatusName.TEST_PROPERTY2.name());
        assertEquals("Property 2", VALUE2, entry2.getValue());

        // Remove the properties
        repository.update(StatusName.TEST_PROPERTY1.name(), null);
        repository.update(StatusName.TEST_PROPERTY2.name(), null);

        // Should return null now
        final StatusEntry entry3 = repository.getValidEntry(StatusName.TEST_PROPERTY1.name());
        assertNull("Property 1 null", entry3.getValue());
        final StatusEntry entry4 = repository.getValidEntry(StatusName.TEST_PROPERTY2.name());
        assertNull("Property 2 null", entry4.getValue());
    }

    /**
     * Tests setting a value with a timeout and reading it both before and
     * after a time.
     * @throws Exception in case of exception
     */
    public void testSetGetTimeout() throws Exception {
        final long expiration = System.currentTimeMillis() + TIMEOUT;
        repository.update(StatusName.TEST_PROPERTY3.name(), VALUE3, expiration);

        // Get the value right away
        final StatusEntry entry1 = repository.getValidEntry(StatusName.TEST_PROPERTY3.name());
        assertEquals("getProperty right away", VALUE3, entry1.getValue());

        // Wait a time (twice the TIMEOUT to be sure)
        try {
            Thread.sleep(2 * TIMEOUT);
        } catch (InterruptedException ex) {
            LOG.error("Sleep was interrupted, the next test might fail.", ex);
        }

        // Now the value should have expired
        final StatusEntry entry2 = repository.getValidEntry(StatusName.TEST_PROPERTY3.name());
        assertNull("getProperty expired", entry2);
    }
}
