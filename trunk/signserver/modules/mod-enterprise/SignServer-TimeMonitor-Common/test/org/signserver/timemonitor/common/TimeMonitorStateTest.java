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
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TimeMonitorStateTest {

    /**
     * Logger for this class.
     */
    private static final Logger LOG = Logger.getLogger(ReportStateTest.class);


    /**
     * Test of fromStateLine method, of class TimeMonitorState.
     */
    @Test
    public void testFromStateLineV1() {
        LOG.info("fromStateLine");
        final String stateLine = "1409141564440,INSYNC,REPORTED,POSITIVE";
        TimeMonitorState result = TimeMonitorState.fromStateLine(stateLine);
        assertEquals(1409141564440L, result.getLastUpdated());
        assertEquals(TimeState.INSYNC, result.getTimeState());
        assertEquals(ReportState.REPORTED, result.getReportState());
        assertEquals(LeapState.POSITIVE, result.getLeapState());
        assertEquals("", result.getConfigVersion());
        assertEquals(0L, result.getOffset());
        assertEquals(0L, result.getQueryTime1());
        assertEquals(0L, result.getQueryTime2());
        assertEquals(0L, result.getReportTime());
    }

    /**
     * Test of fromStateLine method, of class TimeMonitorState.
     */
    @Test
    public void testFromStateLineV2() {
        LOG.info("fromStateLine");
        final String stateLine = "1409141564440,INSYNC,REPORTED,POSITIVE,b526098,13,507,8,7";
        TimeMonitorState result = TimeMonitorState.fromStateLine(stateLine);
        assertEquals(1409141564440L, result.getLastUpdated());
        assertEquals(TimeState.INSYNC, result.getTimeState());
        assertEquals(ReportState.REPORTED, result.getReportState());
        assertEquals(LeapState.POSITIVE, result.getLeapState());
        assertEquals("b526098", result.getConfigVersion());
        assertEquals(13L, result.getOffset());
        assertEquals(507L, result.getQueryTime1());
        assertEquals(8L, result.getQueryTime2());
        assertEquals(7L, result.getReportTime());
    }

    /**
     * Test of createStateLine method, of class TimeMonitorState.
     */
    @Test
    public void testCreateStateLine() {
        LOG.info("createStateLine");
        TimeMonitorState instance = new TimeMonitorState(1409141565555L, TimeState.SOON_OUT_OF_SYNC, ReportState.REPORTED_BUT_EXPIRE_TIME_SHORT, LeapState.NEGATIVE, "123", 3L, 4L, 5L, 6L);
        assertEquals("1409141565555,SOON_OUT_OF_SYNC,REPORTED_BUT_EXPIRE_TIME_SHORT,NEGATIVE,123,3,4,5,6", instance.createStateLine().toString());
    }

    /**
     * Test of toString method, of class TimeMonitorState.
     */
    @Test
    public void testToString() {
        LOG.info("toString");
        TimeMonitorState instance = new TimeMonitorState(1409141565555L, TimeState.SOON_OUT_OF_SYNC, ReportState.REPORTED_BUT_EXPIRE_TIME_SHORT, LeapState.NEGATIVE, "123", 3L, 4L, 5L, 6L);
        assertEquals("1409141565555,SOON_OUT_OF_SYNC,REPORTED_BUT_EXPIRE_TIME_SHORT,NEGATIVE,123,3,4,5,6", instance.toString());
    }

    /**
     * Tests the setter methods, of class TimeMonitorState.
     */
    @Test
    public void testSetters() {
        final String stateLine = "0,INSYNC,REPORTED,NONE,abc,0,0,0,0";

        TimeMonitorState result = TimeMonitorState.fromStateLine(stateLine);
        result.setLastUpdated(1L);
        result.setTimeState(TimeState.OUT_OF_SYNC);
        result.setReportState(ReportState.FAILED_TO_REPORT);
        result.setLeapState(LeapState.UNKNOWN);
        result.setConfigVersion("versionX");
        result.setOffset(6L);
        result.setQueryTime1(7L);
        result.setQueryTime2(8L);
        result.setReportTime(9L);

        assertEquals(1L, result.getLastUpdated());
        assertEquals(TimeState.OUT_OF_SYNC, result.getTimeState());
        assertEquals(ReportState.FAILED_TO_REPORT, result.getReportState());
        assertEquals(LeapState.UNKNOWN, result.getLeapState());
        assertEquals("versionX", result.getConfigVersion());
        assertEquals(6L, result.getOffset());
        assertEquals(7L, result.getQueryTime1());
        assertEquals(8L, result.getQueryTime2());
        assertEquals(9L, result.getReportTime());
    }
}
