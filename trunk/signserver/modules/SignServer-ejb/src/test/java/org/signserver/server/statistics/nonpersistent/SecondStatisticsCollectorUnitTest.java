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
import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;
import org.junit.Test;

import org.signserver.common.NonPersistentStatisticsConstants;
import org.signserver.common.StatisticsConstants;
import org.signserver.common.WorkerConfig;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class SecondStatisticsCollectorUnitTest {

    @Test
    public void testBasics() throws Exception {
        SecondStatisticsCollector mc = genSecondStatisticsCollector(null);

        Calendar currentTime = Calendar.getInstance();
        currentTime.setTimeInMillis(System.currentTimeMillis());

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

        assertTrue(mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);
    }

    private SecondStatisticsCollector genSecondStatisticsCollector(String expireTime) {
        SecondStatisticsCollector ret = new SecondStatisticsCollector();
        WorkerConfig config = new WorkerConfig();
        if (expireTime != null) {
            config.setProperty(NonPersistentStatisticsConstants.SECONDSTATISTICS_EXPIRETIME, expireTime);
        }
        ret.init(123, config, null);

        return ret;
    }
}
