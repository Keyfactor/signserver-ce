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
 * Tests for the TimeState enum.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TimeStateTest {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(TimeStateTest.class);

    /**
     * Test of valueOf method, of class TimeState.
     */
    @Test
    public void testValueOf() {
        LOG.info("valueOf");

        assertEquals(TimeState.INSYNC, TimeState.valueOf("INSYNC"));
        assertEquals(TimeState.OUT_OF_SYNC, TimeState.valueOf("OUT_OF_SYNC"));
        assertEquals(TimeState.SOON_OUT_OF_SYNC, TimeState.valueOf("SOON_OUT_OF_SYNC"));
        assertEquals(TimeState.UNKNOWN, TimeState.valueOf("UNKNOWN"));
    }

}
