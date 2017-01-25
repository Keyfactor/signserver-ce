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

/**
 * The complete state of the TimeMonitor.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TimeMonitorState {

    private long lastUpdated;
    private TimeState timeState;
    private ReportState reportState;
    private LeapState leapState;
    private String configVersion;
    private long offset;
    private long queryTime1;
    private long queryTime2;
    private long reportTime;

    /**
     * Parses a TimeMonitorState from the state line representation.
     * @param stateLine as returned by createStateLine();
     * @return a new instance of a TimeMonitorState parsed from the state line
     * @throws IllegalArgumentException
     * @see TimeMonitorState#createStateLine()
     */
    public static TimeMonitorState fromStateLine(final String stateLine) throws IllegalArgumentException {
        final String[] entries = stateLine.split(",");
        long lastUpdated = Long.parseLong(entries[0]);
        TimeState timeState = TimeState.valueOf(entries[1]);
        ReportState reportState = ReportState.valueOf(entries[2]);
        LeapState leapState = LeapState.valueOf(entries[3]);
        String configVersion;
        long offset;
        long queryTime1;
        long queryTime2;
        long reportTime;
        if (entries.length > 4) { // configVersion, offset, queryTime1, queryTime2, reportTime added in TimeMonitor >= 3.6.0
            configVersion = entries[4];
            offset = Long.parseLong(entries[5]);
            queryTime1 = Long.parseLong(entries[6]);
            queryTime2 = Long.parseLong(entries[7]);
            reportTime = Long.parseLong(entries[8]);
        } else {
            configVersion = "";
            offset = 0;
            queryTime1 = 0;
            queryTime2 = 0;
            reportTime = 0;
        }
        return new TimeMonitorState(lastUpdated, timeState, reportState, leapState, configVersion, offset, queryTime1, queryTime2, reportTime);
    }

    public TimeMonitorState(long lastUpdated, TimeState timeState, ReportState reportState, LeapState leapState, String configVersion, long offset, long queryTime1, long queryTime2, long reportTime) {
        this.lastUpdated = lastUpdated;
        this.timeState = timeState;
        this.reportState = reportState;
        this.leapState = leapState;
        this.configVersion = configVersion;
        this.offset = offset;
        this.queryTime1 = queryTime1;
        this.queryTime2 = queryTime2;
        this.reportTime = reportTime;
    }

    public long getLastUpdated() {
        return lastUpdated;
    }

    public void setLastUpdated(long lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    public TimeState getTimeState() {
        return timeState;
    }

    public void setTimeState(TimeState timeState) {
        this.timeState = timeState;
    }

    public ReportState getReportState() {
        return reportState;
    }

    public void setReportState(ReportState reportState) {
        this.reportState = reportState;
    }

    public LeapState getLeapState() {
        return leapState;
    }

    public void setLeapState(LeapState leapState) {
        this.leapState = leapState;
    }

    public String getConfigVersion() {
        return configVersion;
    }

    public void setConfigVersion(String configVersion) {
        this.configVersion = configVersion;
    }

    public long getOffset() {
        return offset;
    }

    public void setOffset(long offset) {
        this.offset = offset;
    }

    public long getQueryTime1() {
        return queryTime1;
    }

    public void setQueryTime1(long queryTime1) {
        this.queryTime1 = queryTime1;
    }

    public long getQueryTime2() {
        return queryTime2;
    }

    public void setQueryTime2(long queryTime2) {
        this.queryTime2 = queryTime2;
    }

    public long getReportTime() {
        return reportTime;
    }

    public void setReportTime(long reportTime) {
        this.reportTime = reportTime;
    }

    /**
     * @return the state line representation
     * @see TimeMonitorState#fromStateLine(java.lang.String)
     */
    public StringBuilder createStateLine() {
        final StringBuilder buff = new StringBuilder();
        buff.append(lastUpdated).append(",")
                .append(timeState).append(",")
                .append(reportState).append(",")
                .append(leapState.name()).append(",")
                .append(configVersion).append(",")
                .append(offset).append(",")
                .append(queryTime1).append(",")
                .append(queryTime2).append(",")
                .append(reportTime);
        return buff;
    }

    @Override
    public String toString() {
        return createStateLine().toString();
    }

}
