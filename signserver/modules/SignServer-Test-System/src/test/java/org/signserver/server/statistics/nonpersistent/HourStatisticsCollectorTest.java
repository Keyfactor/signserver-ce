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

import java.util.Calendar;
import java.util.List;

import junit.framework.TestCase;

import org.signserver.common.NonPersistentStatisticsConstants;
import org.signserver.common.StatisticsConstants;
import org.signserver.common.WorkerConfig;
import org.signserver.server.statistics.Event;
import org.signserver.server.statistics.StatisticsEntry;

public class HourStatisticsCollectorTest extends TestCase {

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    public void testBasics() throws Exception {
        HourStatisticsCollector hc = genHourStatisticsCollector(null);

        Calendar currentTime = Calendar.getInstance();
        currentTime.setTimeInMillis(System.currentTimeMillis());

        assertNotNull(hc.genCurrentStartPeriod());
        Calendar currentStartTime = Calendar.getInstance();
        currentStartTime.setTime(hc.genCurrentStartPeriod());
        assertTrue(currentTime.get(Calendar.DAY_OF_MONTH) == currentStartTime.get(Calendar.DAY_OF_MONTH));
        assertTrue(currentTime.get(Calendar.HOUR) == currentStartTime.get(Calendar.HOUR));
        assertTrue(currentStartTime.get(Calendar.MINUTE) == 0);
        assertTrue(currentStartTime.get(Calendar.SECOND) == 0);
        assertTrue(currentStartTime.get(Calendar.MILLISECOND) == 0);

        assertNotNull(hc.genCurrentEndPeriod());
        Calendar currentEndTime = Calendar.getInstance();
        currentEndTime.setTime(hc.genCurrentEndPeriod());
        assertTrue(currentTime.get(Calendar.DAY_OF_MONTH) == currentEndTime.get(Calendar.DAY_OF_MONTH));
        assertTrue(currentTime.get(Calendar.HOUR) == currentEndTime.get(Calendar.HOUR));
        assertTrue(currentEndTime.get(Calendar.MINUTE) == 59);
        assertTrue(currentEndTime.get(Calendar.SECOND) == 59);
        assertTrue(currentEndTime.get(Calendar.MILLISECOND) == 999);
        assertTrue("" + hc.getExpireTime(), hc.getExpireTime() == (Long.parseLong(NonPersistentStatisticsConstants.DEFAULT_HOURSTATISTICS_EXPIRETIME) * 1000));

        assertTrue(hc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);

        hc.addEvent(getEvent());
        hc.addEvent(getEvent());
        List<StatisticsEntry> list = hc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null);
        assertTrue(list.size() == 1);
        assertTrue(list.get(0).getNumberOfEvents() == 2);

        hc.flush();
        assertTrue(hc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);
    }

    public void testFifoQueue() throws Exception {
        HourStatisticsCollector hc = genHourStatisticsCollector("1");
        hc.addEvent(getEvent());
        assertTrue(hc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 1);
        Thread.sleep(1050);
        assertTrue(hc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);

    }

    private HourStatisticsCollector genHourStatisticsCollector(String expireTime) {
        HourStatisticsCollector ret = new HourStatisticsCollector();
        WorkerConfig config = new WorkerConfig();
        if (expireTime != null) {
            config.setProperty(NonPersistentStatisticsConstants.HOURSTATISTICS_EXPIRETIME, expireTime);
        }
        ret.init(123, config, null);

        return ret;
    }

    private Event getEvent() throws InterruptedException {
        Event event = new Event(123);
        event.start();
        Thread.sleep(10);
        event.stop();
        return event;
    }
}
