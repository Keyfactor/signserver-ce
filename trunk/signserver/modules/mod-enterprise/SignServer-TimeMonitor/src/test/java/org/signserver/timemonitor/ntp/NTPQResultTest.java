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

import org.apache.log4j.Logger;

import junit.framework.TestCase;
import org.signserver.timemonitor.common.LeapState;

/**
 * Test for NTPQResult
 *
 * @author Marcus Lundblad
 * @version $Id: NTPQResultTest.java 4562 2012-12-10 12:14:02Z marcus $
 */
public class NTPQResultTest extends TestCase {

    private static final Logger LOG = Logger.getLogger(NTPQResultTest.class);

    /**
     * Test of get methods.
     *
     * @throws Exception
     */
    public void testGetters() throws Exception {
        LOG.info("testGetters");
        NTPQResult instance = new NTPQResult(42, "Test error", LeapState.POSITIVE);

        assertEquals("getExitCode", 42, instance.getExitCode());
        assertEquals("getErrorMessage", "Test error", instance.getErrorMessage());
        assertEquals("getLeapState", LeapState.POSITIVE, instance.getLeapState());
    }

    /**
     * Test the equals method.
     *
     * @throws Exception
     */
    public void testEquals() throws Exception {
        LOG.info("testEquals");
       NTPQResult instance0M1P = new NTPQResult(0, "M1", LeapState.POSITIVE);
       NTPQResult instance0M1NE = new NTPQResult(0, "M1", LeapState.NEGATIVE);
       NTPQResult instance0M1NO = new NTPQResult(0, "M1", LeapState.NONE);
       NTPQResult instance1M1P = new NTPQResult(1, "M1", LeapState.POSITIVE);
       NTPQResult instance0M2P = new NTPQResult(0, "M2", LeapState.POSITIVE);
       NTPQResult instance0M1P2 = new NTPQResult(0, "M1", LeapState.POSITIVE);

       // check that equal objects are really equal
       assertTrue(instance0M1P.equals(instance0M1P));
       assertTrue(instance0M1NE.equals(instance0M1NE));
       assertTrue(instance0M1NO.equals(instance0M1NO));
       assertTrue(instance1M1P.equals(instance1M1P));
       assertTrue(instance0M2P.equals(instance0M2P));

       // check that two distinct instances having equal properties qualify as equal
       assertTrue(instance0M1P.equals(instance0M1P2));

       // check that two instances with equal exit code, but differs don't qualify as equal
       assertFalse(instance0M1P.equals(instance0M1NE));

       // check that two instances with equal leap state, but differs don't equals
       assertFalse(instance0M1P.equals(instance0M2P));
    }
}
