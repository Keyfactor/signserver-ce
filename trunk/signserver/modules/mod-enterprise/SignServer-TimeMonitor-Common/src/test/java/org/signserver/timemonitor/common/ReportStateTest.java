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
 * Tests for the ReportState enum.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ReportStateTest {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(ReportStateTest.class);

    /**
     * Test of valueOf method, of class ReportState.
     */
    @Test
    public void testValueOf() {
        LOG.info("valueOf");

        assertEquals(ReportState.FAILED_TO_REPORT, ReportState.valueOf("FAILED_TO_REPORT"));
        assertEquals(ReportState.REPORTED, ReportState.valueOf("REPORTED"));
        assertEquals(ReportState.REPORTED_BUT_EXPIRE_TIME_SHORT, ReportState.valueOf("REPORTED_BUT_EXPIRE_TIME_SHORT"));
    }

}
