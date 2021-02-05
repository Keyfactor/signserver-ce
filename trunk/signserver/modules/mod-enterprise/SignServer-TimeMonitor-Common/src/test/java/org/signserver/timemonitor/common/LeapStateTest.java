/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
