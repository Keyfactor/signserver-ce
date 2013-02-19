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
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;
import org.signserver.common.NonPersistentStatisticsConstants;
import org.signserver.common.StatisticsConstants;
import org.signserver.common.WorkerConfig;
import org.signserver.server.statistics.Event;
import org.signserver.server.statistics.StatisticsEntry;

import junit.framework.TestCase;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class SecondStatisticsCollectorTest extends TestCase {
    /** Logger for this class */
    Logger LOG = Logger.getLogger(SecondStatisticsCollectorTest.class);
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    public void testBasics() throws Exception {
        final long baseTime = System.currentTimeMillis();
        final Calendar currentTime = Calendar.getInstance();
        currentTime.setTimeInMillis(baseTime);
        
        SecondStatisticsCollectorMock mc = genSecondStatisticsCollector(baseTime, null);

        assertNotNull(mc.genCurrentStartPeriod());
        Calendar currentStartTime = Calendar.getInstance();
        currentStartTime.setTime(mc.genCurrentStartPeriod());
        assertTrue(currentTime.get(Calendar.DAY_OF_MONTH) == currentStartTime.get(Calendar.DAY_OF_MONTH));
        assertTrue(currentTime.get(Calendar.HOUR) == currentStartTime.get(Calendar.HOUR));
        assertTrue(currentTime.get(Calendar.MINUTE) == currentStartTime.get(Calendar.MINUTE));
        assertTrue(currentTime.get(Calendar.SECOND) == currentStartTime.get(Calendar.SECOND));
        assertTrue(currentStartTime.get(Calendar.MILLISECOND) == 0);
        assertNotNull(mc.genCurrentEndPeriod());

        Calendar currentEndTime = Calendar.getInstance();
        currentEndTime.setTime(mc.genCurrentEndPeriod());
        assertTrue(currentTime.get(Calendar.DAY_OF_MONTH) == currentEndTime.get(Calendar.DAY_OF_MONTH));
        assertTrue(currentTime.get(Calendar.HOUR) == currentEndTime.get(Calendar.HOUR));
        assertTrue(currentTime.get(Calendar.MINUTE) == currentEndTime.get(Calendar.MINUTE));
        assertTrue(currentTime.get(Calendar.SECOND) == currentEndTime.get(Calendar.SECOND));
        assertTrue(currentEndTime.get(Calendar.MILLISECOND) == 999);

        assertTrue(mc.getExpireTime() == (Long.parseLong(NonPersistentStatisticsConstants.DEFAULT_SECONDSTATISTICS_EXPIRETIME) * 1000));

        assertEquals(0, mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size());

        final long currTime = currentStartTime.getTimeInMillis();
        mc.addEvent(getEvent(currTime));
        // simulate that it took 10 ms to generate the event
        mc.addTime(10);
        
        mc.addEvent(getEvent(currTime + 10));
       
        assertEquals(1, mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size());

        // simulate sleeping
        mc.addTime(1100);

        mc.addEvent(getEvent(currTime + 1110));
        
        assertEquals(2, mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size());

       
        mc.flush();
        assertEquals(0, mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size());
    }

    public void testFifoQueue() throws Exception {
        // start the mock timer at the current system time
        final long baseTime = System.currentTimeMillis();
        SecondStatisticsCollectorMock mc = genSecondStatisticsCollector(baseTime, "3");
        
        long time = baseTime;
        mc.addEvent(getEvent(time));
        // simulate sleeping plus extra time for generating the event
        mc.addTime(1050 + 10);
        time += 1050 + 10;
        
        mc.addEvent(getEvent(time));
        // simulate sleeping plus extra time for generating the event
        mc.addTime(1050 + 10);
        time += 1050 + 10;
        
        mc.addEvent(getEvent(time));
        // simulate generate the event taking 10 ms.
        mc.addTime(10);
        time += 10;
               
        assertEquals(3, mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size());
        assertEquals(1, mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, new Date(time - 1000), null).size());
        assertTrue(mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, new Date(time - 3100), new Date(time - 1100)).size() > 1);
        assertEquals(2, mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, new Date(time - 1000)).size());

        // simulate sleeping
        mc.addTime(1050);
        assertEquals(2, mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size());
    }

    private SecondStatisticsCollectorMock genSecondStatisticsCollector(final long baseTime, final String expireTime) {
        SecondStatisticsCollectorMock ret = new SecondStatisticsCollectorMock(baseTime);

        WorkerConfig config = new WorkerConfig();
        if (expireTime != null) {
            config.setProperty(NonPersistentStatisticsConstants.SECONDSTATISTICS_EXPIRETIME, expireTime);
        }
        ret.init(123, config, null);

        return ret;
    }

    private Event getEvent(final long baseTime) throws InterruptedException {
        Event event = new Event(123) {
            @Override
            public void start() {
                setStartTimeStamp(new Date(baseTime));
            }
            
            @Override
            public void stop() {
                setEndTimeStamp(new Date(baseTime + 10));
            }
        };
        
        event.start();
        event.stop();
        
        return event;
    }
    
    private class SecondStatisticsCollectorMock extends SecondStatisticsCollector {
        private long currTime;
        
        public SecondStatisticsCollectorMock(final long baseTime) {
            currTime = baseTime;
        }

        public void addTime(final long sleep) {
            currTime += sleep;
        }
        
        @Override
        protected long getCurrentTime() {
            return currTime;
        }

        @Override
        protected Date genCurrentStartPeriod() {
            Calendar cal = Calendar.getInstance();
            cal.setTimeInMillis(currTime);
            cal.set(Calendar.MILLISECOND, 0);
            return cal.getTime();
        }

        @Override
        protected Date genCurrentEndPeriod() {
            Calendar cal = Calendar.getInstance();
            cal.setTimeInMillis(currTime);
            cal.set(Calendar.MILLISECOND, 999);
            return cal.getTime();
        }
        
        @Override
        protected StatisticsEntry createStatisticsEntry(final Date periodStart, final Date periodEnd, final Date expireDate) {
            // returns a StatisticsEntry entirely bound to the mock time
            return new StatisticsEntry(periodStart, periodEnd, expireDate) {
                @Override
                public long getDelay(TimeUnit unit) {
                    return unit.convert(expireDate.getTime() - currTime, TimeUnit.MILLISECONDS);
                }
            };
        }
        
    }
}
