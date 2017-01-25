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
