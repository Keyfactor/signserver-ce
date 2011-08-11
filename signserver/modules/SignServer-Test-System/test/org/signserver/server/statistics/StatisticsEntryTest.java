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

import junit.framework.TestCase;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class StatisticsEntryTest extends TestCase {

    private static Date expireDate = new Date(System.currentTimeMillis() + 2000);
    private static StatisticsEntry sE = new StatisticsEntry(new Date(System.currentTimeMillis() - 100), new Date(System.currentTimeMillis() + 100), expireDate);

    public void testAddEvent() throws InterruptedException {
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

        assertTrue(sE.getNumberOfEvents() == 3);
        assertTrue(sE.getCustomData().get("CUSTOMKEY").equals(246));
    }

    public void testGetExpireDate() {
        assertEquals(sE.getExpireDate(), expireDate);
    }

    public void testGetDelay() throws InterruptedException {
        Thread.sleep(100);
        assertTrue("" + sE.getDelay(TimeUnit.NANOSECONDS), sE.getDelay(TimeUnit.NANOSECONDS) > 0);
        Thread.sleep(2100);
        assertTrue(sE.getDelay(TimeUnit.NANOSECONDS) < 0);
    }

    private Event getEvent() throws InterruptedException {
        Event event = new Event(123);
        event.start();
        Thread.sleep(10);
        event.stop();
        return event;
    }
}
