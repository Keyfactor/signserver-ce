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
package org.signserver.server.statistics.nonpersistent;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.DelayQueue;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.statistics.Event;
import org.signserver.server.statistics.IStatisticsCollector;
import org.signserver.server.statistics.StatisticsEntry;

/**
 * Base class containing help methods to implement
 * a StatisticsCollector using a FIFO queue stored in
 * memory.
 * 
 * @author Philip Vendil 28 apr 2008
 * @version $Id$
 */
public abstract class BaseFIFOStatisticsCollector implements IStatisticsCollector {
    protected int workerId = 0;
    protected WorkerConfig config;
    protected EntityManager em;
    protected StatisticsEntry currentStatisticsEntry;
    protected DelayQueue<StatisticsEntry> fIFOQueue = new DelayQueue<StatisticsEntry>();
    
    private Long expireTime;

    /**
     * Initialization method that should be called directly after creation
     */
    public void init(int workerId, WorkerConfig config, EntityManager em) {
        this.workerId = workerId;
        this.config = config;
        this.em = em;
    }

    /**
     * @see org.signserver.server.statistics.IStatisticsCollector#addEvent(org.signserver.server.statistics.Event)
     */
    public void addEvent(Event event) throws SignServerException {
        Date endPeriod = genCurrentEndPeriod();
        Date startPeriod = genCurrentStartPeriod();
        if (currentStatisticsEntry != null) {
            if (endPeriod == null || System.currentTimeMillis() > currentStatisticsEntry.getPeriodEnd().getTime()) {
                currentStatisticsEntry = null;
            }
        }

        if (currentStatisticsEntry == null) {
            if (endPeriod == null || startPeriod == null) {
                currentStatisticsEntry = new StatisticsEntry(new Date(), new Date(), new Date(getExpireTime() + System.currentTimeMillis()));
            } else {
                currentStatisticsEntry = new StatisticsEntry(startPeriod, endPeriod, new Date(getExpireTime() + System.currentTimeMillis()));
            }
            fIFOQueue.add(currentStatisticsEntry);
        }

        currentStatisticsEntry.addEvent(event);
        while (fIFOQueue.poll() != null);
    }

    /**
     * @see org.signserver.server.statistics.IStatisticsCollector#flush()
     */
    public void flush() {
        fIFOQueue.clear();
    }

    /** 
     * Returns the expire time in seconds before a statistics entry should be
     * considered as invalid.
     * @return expire time in seconds or 0 if no statistics of this kind should
     * be done.
     */
    public abstract long getExpireTime();

    /**
     * 
     * @return the date when the current statistics object should
     * be added to queue or null if the event always should be
     * added to the queue.
     */
    protected abstract Date genCurrentEndPeriod();

    /**
     * 
     * @return the date when the current statistics object should
     * be added to queue or null if the event always should be
     * added to the queue.
     */
    protected abstract Date genCurrentStartPeriod();

    /**
     * Help method to fetch the expire time.
     */
    protected long getExpireTime(String settingKey, String defaultValue, Logger log) {
        if (expireTime == null) {
            long eTime = Long.parseLong(defaultValue);
            try {
                eTime = Long.parseLong(config.getProperties().getProperty(settingKey, defaultValue));
            } catch (NumberFormatException e) {
                log.error("Error in Statistics Collector for " + workerId + " setting " + settingKey + " should only contain numbers, using default value of : " + defaultValue);
            }
            expireTime = eTime * 1000;
        }
        return expireTime;
    }

    /**
     * Help method used to fetch matching statistics entries
     */
    protected List<StatisticsEntry> fetchStatistics(Date startTime, Date endTime) {
        List<StatisticsEntry> retval = new ArrayList<StatisticsEntry>();
        
        // First pop old statistics entries
        while (fIFOQueue.poll() != null);

        for (StatisticsEntry next : fIFOQueue) {
            if (endTime != null && next.getPeriodStart().after(endTime)) {
                break;
            }
            if (startTime == null || next.getPeriodStart().after(startTime)) {
                retval.add(next);
            }
        }
        return retval;
    }
}
