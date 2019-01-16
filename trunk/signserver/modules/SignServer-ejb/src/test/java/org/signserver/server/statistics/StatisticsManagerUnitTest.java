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

import org.signserver.common.StatisticsConstants;
import org.signserver.common.WorkerConfig;

import static org.junit.Assert.*;
import org.junit.Test;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class StatisticsManagerUnitTest {

    @Test
    public void testAll() throws Exception {
        WorkerConfig wc = new WorkerConfig();
        assertNull(StatisticsManager.startEvent(123, wc, null));
        StatisticsManager.endEvent(123, wc, null, null);

        wc.setProperty(StatisticsConstants.TYPE, StatisticsConstants.TYPE_NONPERSISTANT);
        Event event = StatisticsManager.startEvent(123, wc, null);
        assertNotNull(event);
        assertNotNull(event.getStartTimeStamp());
        assertNull(event.getEndTimeStamp());

        StatisticsManager.endEvent(123, wc, null, event);
        event = StatisticsManager.startEvent(123, wc, null);
        Event event2 = StatisticsManager.startEvent(123, wc, null);
        StatisticsManager.endEvent(123, wc, null, event);
        StatisticsManager.endEvent(123, wc, null, event2);

        event = StatisticsManager.startEvent(124, wc, null);
        StatisticsManager.endEvent(124, wc, null, event);

        IStatisticsCollector sc = StatisticsManager.getStatisticsCollector(123, wc, null);
        assertTrue(sc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).get(3).getNumberOfEvents() == 3);

        StatisticsManager.flush(123);
        sc = StatisticsManager.getStatisticsCollector(123, wc, null);
        assertTrue(sc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);
        event = StatisticsManager.startEvent(123, wc, null);
        event2 = StatisticsManager.startEvent(123, wc, null);
        StatisticsManager.endEvent(123, wc, null, event);
        StatisticsManager.endEvent(123, wc, null, event2);
        assertFalse(sc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);
        StatisticsManager.flush(0);
        sc = StatisticsManager.getStatisticsCollector(123, wc, null);
        assertTrue(sc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);
    }
}
