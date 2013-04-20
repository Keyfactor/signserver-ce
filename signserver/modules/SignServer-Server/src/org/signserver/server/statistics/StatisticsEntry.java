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
package org.signserver.server.statistics;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Delayed;
import java.util.concurrent.TimeUnit;
import org.signserver.server.statistics.Event;

/**
 * A statistics entry is a summarization of one or more events
 * during a defined period of time, either as a single event or
 * longer such as minute or hour.
 * 
 * @author Philip Vendil 28 apr 2008
 * @version $Id$
 */
public class StatisticsEntry implements Delayed {

    private Date periodStart;
    private Date periodEnd;
    private Date expireDate;
    private Map<String, Integer> customData;
    private Integer numberOfEvents = 0;

    /**
     * Creates one StatisticsEntry object.
     * 
     * @param periodStart defining the start of this collection of statistics
     * @param periodEnd defining the end of this collection of statistics
     * @param expireDate the date when this entry will be expired and removed from the
     * StatisticsCollector.
     */
    public StatisticsEntry(Date periodStart, Date periodEnd, Date expireDate) {
        this.periodStart = periodStart;
        this.periodEnd = periodEnd;
        this.expireDate = expireDate;
    }

    /**
     * Method to add the records of this event to the statistics collector. 
     */
    public void addEvent(Event event) {
        numberOfEvents++;
        if (event.getCustomData() != null) {
            for (String next : event.getCustomData().keySet()) {
                if (customData == null) {
                    customData = new HashMap<String, Integer>();
                }
                if (customData.get(next) == null) {
                    customData.put(next, event.getCustomData().get(next));
                } else {
                    customData.put(next, customData.get(next) + event.getCustomData().get(next));
                }
            }
        }
    }

    /**
     * @return the timestamp when this statistics started.
     */
    public Date getPeriodStart() {
        return periodStart;
    }

    /**
     * @return the timestamp when this statistics ended.
     */
    public Date getPeriodEnd() {
        return periodEnd;
    }

    /**
     * @return The defined expire date
     */
    Date getExpireDate() {
        return expireDate;
    }

    /**
     * @return the Number of events that have occurred during the
     * defined period of time.
     */
    public Integer getNumberOfEvents() {
        return numberOfEvents;
    }

    /**
     * @return the custom data used for this event or null
     * if no custom data have been recorded.
     */
    Map<String, Integer> getCustomData() {
        return customData;
    }

    /**
     * 
     * Returns the remaining delay associated with this object, in the given time unit. 
     * @param unit the time unit
     * @return the remaining time in the specified unit.
     */
    @Override
    public long getDelay(TimeUnit unit) {
        return unit.convert(expireDate.getTime() - System.currentTimeMillis(), TimeUnit.MILLISECONDS);
    }

    @Override
    public int compareTo(Delayed o) {
        if (o instanceof StatisticsEntry) {
            return expireDate.compareTo(((StatisticsEntry) o).getExpireDate());
        }
        return 0;
    }
}
