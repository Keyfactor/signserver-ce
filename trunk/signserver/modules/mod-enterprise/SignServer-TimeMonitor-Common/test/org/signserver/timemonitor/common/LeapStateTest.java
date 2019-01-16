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
package org.signserver.timemonitor.common;

import org.apache.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for the LeapState enum.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class LeapStateTest {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(LeapStateTest.class);

    /**
     * Test of valueOf method, of class LeapState.
     */
    @Test
    public void testValueOf() {
        LOG.info("valueOf");

        assertEquals(LeapState.UNKNOWN, LeapState.valueOf("UNKNOWN"));
        assertEquals(LeapState.NONE, LeapState.valueOf("NONE"));
        assertEquals(LeapState.POSITIVE, LeapState.valueOf("POSITIVE"));
        assertEquals(LeapState.NEGATIVE, LeapState.valueOf("NEGATIVE"));
    }

}
