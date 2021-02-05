/** ***********************************************************************
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
 ************************************************************************ */
package org.signserver.client.cli.defaultimpl;

import java.util.ArrayList;
import java.util.List;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNull;
import org.junit.Test;

/**
 * Unit tests for HostManager methods.
 *
 * @author Vinay Singh
 * @version $Id$
 */
public class HostManagerTest {

    /**
     * Test checking that getNextHostForRequest works as expected with no load
     * balancing.
     *
     * @throws Exception
     */
    @Test
    public void test01GetNextHostNoLoadBalancing() throws Exception {
        List<String> participantHosts = new ArrayList<>();
        participantHosts.add("host1");
        participantHosts.add("host2");
        participantHosts.add("host3");
        MockHostManager hostManager = new MockHostManager(participantHosts, false);
        assertEquals("host1", hostManager.getNextHostForRequest());
        assertEquals("host1", hostManager.getNextHostForRequest());
        assertEquals("host1", hostManager.getNextHostForRequest());
        assertEquals("host1", hostManager.getNextHostForRequest());
        assertEquals("host1", hostManager.getNextHostForRequest());
        assertEquals("host1", hostManager.getNextHostForRequest());
    }

    /**
     * Test checking that HostManager methods work as expected with no load
     * balancing but with connection failure.
     *
     * @throws Exception
     */
    @Test
    public void test02GetNextHostNoLoadBalancingWithConnectionFailure() throws Exception {
        List<String> participantHosts = new ArrayList<>();
        participantHosts.add("host1");
        participantHosts.add("host2");
        participantHosts.add("host3");
        MockHostManager hostManager = new MockHostManager(participantHosts, false);
        assertEquals("host1", hostManager.getNextHostForRequest());
        assertEquals("host1", hostManager.getNextHostForRequest());

        // failure
        hostManager.removeHost("host1");
        assertEquals("host2", hostManager.getNextHostForRequestWhenFailure());
        hostManager.removeHost("host2");
        assertEquals("host3", hostManager.getNextHostForRequestWhenFailure());

        // now only host3 is left in list
        assertEquals("host3", hostManager.getNextHostForRequest());
        assertEquals("host3", hostManager.getNextHostForRequest());

        // failure 
        hostManager.removeHost("host3");
        // now no host should be available for retry
        assertNull("No more host available to try", hostManager.getNextHostForRequestWhenFailure());

    }

    /**
     * Test checking that getNextHostForRequest works as expected with
     * ROUND_ROBIN load balancing.
     *
     * @throws Exception
     */
    @Test
    public void test03GetNextHostWithLoadBalancing() throws Exception {
        List<String> participantHosts = new ArrayList<>();
        participantHosts.add("host1");
        participantHosts.add("host2");
        participantHosts.add("host3");
        participantHosts.add("host4");

        MockHostManager hostManager = new MockHostManager(participantHosts, true);

        assertEquals("host2", hostManager.getNextHostForRequest());
        assertEquals("host3", hostManager.getNextHostForRequest());
        assertEquals("host4", hostManager.getNextHostForRequest());
        assertEquals("host1", hostManager.getNextHostForRequest());
        assertEquals("host2", hostManager.getNextHostForRequest());
        assertEquals("host3", hostManager.getNextHostForRequest());
        assertEquals("host4", hostManager.getNextHostForRequest());
    }

    /**
     * Test checking that HostManager work as expected with ROUND_ROBIN load
     * balancing but with connection failure.
     *
     * @throws Exception
     */
    @Test
    public void test04GetNextHostWithLoadBalancingWithConnectionFailure() throws Exception {
        List<String> participantHosts = new ArrayList<>();
        participantHosts.add("host1");
        participantHosts.add("host2");
        participantHosts.add("host3");
        participantHosts.add("host4");

        MockHostManager hostManager = new MockHostManager(participantHosts, true);

        assertEquals("host2", hostManager.getNextHostForRequest());
        assertEquals("host3", hostManager.getNextHostForRequest());
        assertEquals("host4", hostManager.getNextHostForRequest());

        // failure
        assertEquals("host1", hostManager.getNextHostForRequest());
        hostManager.removeHost("host1");

        assertEquals("host2", hostManager.getNextHostForRequestWhenFailure());

        // failure
        assertEquals("host3", hostManager.getNextHostForRequest());
        hostManager.removeHost("host3");

        // Now host1 & host3 should not be present in list
        assertEquals("host4", hostManager.getNextHostForRequestWhenFailure());
        assertEquals("host2", hostManager.getNextHostForRequest());
        assertEquals("host4", hostManager.getNextHostForRequest());
    }

}
