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
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;

import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class StatisticsEntryTest {
    /** Logger for this class. */
    Logger LOG = Logger.getLogger(StatisticsEntryTest.class);
    
    private Date expireDate;
    private StatisticsEntry sE;
  
    @Before
    public void setUp() throws Exception {
        final long now = System.currentTimeMillis();
        expireDate = new Date(now + 2000);
        sE = new StatisticsEntry(new Date(now - 100), new Date(now + 100), expireDate);
    }

    @Test
    public void test01AddEvent() throws InterruptedException {
        Event event1 = getEvent();
        event1.addCustomStatistics("CUSTOMKEY", 123);
        Thread.sleep(10);
        Event event2 = getEvent();
        event2.addCustomStatistics("CUSTOMKEY", 123);
        Thread.sleep(10);
        Event event3 = getEvent();

        sE.addEvent(event1);
        sE.addEvent(event2);
        sE.addEvent(event3);

        assertEquals(Integer.valueOf(3), sE.getNumberOfEvents());
        assertEquals(Integer.valueOf(123 + 123), sE.getCustomData().get("CUSTOMKEY"));
    }

    @Test
    public void test02GetExpireDate() {
        assertEquals(sE.getExpireDate(), expireDate);
    }

    @Test
    public void test03GetDelay() throws InterruptedException {
        final long before = System.currentTimeMillis();
        final long delayBefore = sE.getDelay(TimeUnit.MILLISECONDS);
        
        Thread.sleep(100);
        final long after = System.currentTimeMillis();
        final long elapsed = after - before;
        final long delayAfter = sE.getDelay(TimeUnit.MILLISECONDS);
        final long delayDiff = delayBefore - delayAfter;
        
        LOG.info("testGetDelay: elapsed time: " + elapsed);
        LOG.info("testGetDelay: delay diff: " + delayDiff);
        assertTrue("Delay should have decreased: " + delayDiff, delayDiff > 0);
        assertTrue("Delay should now have decreased more than elapsed time: " + delayDiff, delayDiff <= elapsed);
        
        // sleep for a period longer than the expire time, delay should have passed 0
        Thread.sleep(2100);
        assertTrue("Delay should have reached 0", sE.getDelay(TimeUnit.NANOSECONDS) < 0);
    }

    private Event getEvent() throws InterruptedException {
        Event event = new Event(123);
        event.start();
        Thread.sleep(10);
        event.stop();
        return event;
    }
}
