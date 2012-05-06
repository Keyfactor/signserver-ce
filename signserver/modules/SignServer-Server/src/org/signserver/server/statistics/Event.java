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

/**
 * An Event is the base element in collecting statistics.
 *
 * <p>This base class records when in time the event started and
 * when it stopped for a particular workerId. It is possible
 * to extend the statistics collection even further adding
 * custom data to the event specific for a particular worker.</p>
 * 
 * <p> To add custom data just define a type to call it and
 * use the addCustomData method. The type should be unique and
 * supported by the tool used to review the statistics. </p>
 *
 * <p>It's main methods are start() and stop() that should
 * be called whenever the particular event have started
 * and when it have stopped.</p>
 * 
 * @author Philip Vendil 28 apr 2008
 * @version $Id$
 */
public class Event {

    private Date startTimeStamp;
    
    private Date endTimeStamp;
    
    private int workerId = 0;
    
    private Map<String, Integer> customData;

    public Event(int workerId) {
        this.workerId = workerId;
    }

    /**
     * Marks the event as started by setting the timestamp
     */
    public void start() {
        this.startTimeStamp = new Date();
    }

    /**
     * Marks the event as ended by setting the timestamp
     */
    public void stop() {
        this.endTimeStamp = new Date();
    }

    /**
     * @return the endTimeStamp
     */
    public int getWorkerId() {
        return workerId;
    }

    /**
     * @return the time the event started or null if it haven't started yet.
     */
    public Date getStartTimeStamp() {
        return startTimeStamp;
    }

    /**
     * @return @return the time the event started or null if it haven't ended yet.
     */
    public Date getEndTimeStamp() {
        return endTimeStamp;
    }

    /**
     * Method used to add custom statistics data. Makes
     * the statistics collection more resource intensive.
     * 
     * @param type unique name of the data that should be unique.
     * The statistics viewer used must support this type.
     * @param data the data to record.
     */
    public void addCustomStatistics(String type, Integer data) {
        if (customData == null) {
            customData = new HashMap<String, Integer>();
        }
        customData.put(type, data);
    }

    /**
     * @return the custom data used for this event or null
     * if no custom data have been recorded.
     */
    public Map<String, Integer> getCustomData() {
        return customData;
    }
}
