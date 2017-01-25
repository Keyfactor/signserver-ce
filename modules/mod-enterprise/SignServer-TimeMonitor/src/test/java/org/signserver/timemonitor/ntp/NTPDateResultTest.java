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
package org.signserver.timemonitor.ntp;

import junit.framework.TestCase;

/**
 * Tests for the NTPDateResult class.
 *
 * @author Markus Kilås
 * @version $Id: NTPDateResultTest.java 4462 2012-11-13 08:54:00Z markus $
 */
public class NTPDateResultTest extends TestCase {

    public NTPDateResultTest(String testName) {
        super(testName);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test of getters of class NTPDateResult.
     */
    public void testGetters() {
        System.out.println("getDelay");

        NTPDateResult instance = new NTPDateResult(-4, "error2", "server2", 15, -0.78, 0.13, false);
        assertEquals("delay", 0.13, instance.getDelay());
        assertEquals("errorMessage", "error2", instance.getErrorMessage());
        assertEquals("exitCode", -4, instance.getExitCode());
        assertEquals("offset", -0.78, instance.getOffset());
        assertEquals("server", "server2", instance.getServer());
        assertEquals("stratum", 15, instance.getStratum());
        assertFalse("rateLimited", instance.isRateLimited());
    }

    /**
     * Test of equals method, of class NTPDateResult.
     */
    @SuppressWarnings("IncompatibleEquals")
    public void testEquals() {
        System.out.println("equals");

        NTPDateResult instanceA1 = new NTPDateResult(-4, "error2", "server2", 15, -0.78, 0.13, false);
        NTPDateResult instanceA2 = new NTPDateResult(-4, "error2", "server2", 15, -0.78, 0.13, false);
        NTPDateResult instanceB = new NTPDateResult(-5, "error2", "server2", 15, -0.78, 0.13, false);
        NTPDateResult instanceC = new NTPDateResult(-4, "error3", "server2", 15, -0.78, 0.13, false);
        NTPDateResult instanceD = new NTPDateResult(-4, "error2", "server3", 15, -0.78, 0.13, false);
        NTPDateResult instanceE = new NTPDateResult(-4, "error2", "server2", 16, -0.78, 0.13, false);
        NTPDateResult instanceF = new NTPDateResult(-4, "error2", "server2", 15, -0.78, 0.13, false);
        NTPDateResult instanceG = new NTPDateResult(-4, "error2", "server2", 15, -0.78, 0.14, false);
        NTPDateResult instanceH = new NTPDateResult(-4, null, "server2", 15, -0.78, 0.13, false);
        NTPDateResult instanceI = new NTPDateResult(-4, "error2", null, 15, -0.78, 0.13, false);
        NTPDateResult instanceJ = new NTPDateResult(-4, "error2", "server2", 15, 0.78, 0.13, false);
        String instanceK = "something else";
        NTPDateResult instanceL = null;
        NTPDateResult instanceM =
                new NTPDateResult(-4, "error2", "server2", 15, -0.78, 0.13, true);
        
        // A1 equals A2 and vice versa
        assertTrue(instanceA1.equals(instanceA1));
        assertTrue(instanceA1.equals(instanceA2));
        assertTrue(instanceA2.equals(instanceA1));
        assertTrue(instanceA2.equals(instanceA2));

        // None of the other equals each other
        assertFalse(instanceA2.equals(instanceB));
        assertFalse(instanceB.equals(instanceC));
        assertFalse(instanceC.equals(instanceD));
        assertFalse(instanceD.equals(instanceE));
        assertFalse(instanceE.equals(instanceF));
        assertFalse(instanceF.equals(instanceG));
        assertFalse(instanceG.equals(instanceH));
        assertFalse(instanceH.equals(instanceI));
        assertFalse(instanceI.equals(instanceJ));
        assertFalse(instanceJ.equals(instanceK));
        assertFalse(instanceK.equals(instanceA1));
        assertFalse(instanceA1.equals(instanceL));
        assertFalse(instanceA1.equals(instanceM));
    }

}
