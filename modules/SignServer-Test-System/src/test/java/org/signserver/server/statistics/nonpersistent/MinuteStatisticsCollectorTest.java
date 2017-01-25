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

import junit.framework.TestCase;

import org.signserver.common.NonPersistentStatisticsConstants;
import org.signserver.common.StatisticsConstants;
import org.signserver.common.WorkerConfig;
import org.signserver.server.statistics.Event;

public class MinuteStatisticsCollectorTest extends TestCase {

        @Override
	protected void setUp() throws Exception {
		super.setUp();
	}
	
	public void testBasics() throws Exception {
		MinuteStatisticsCollector mc = genMinuteStatisticsCollector(null);
		
		Calendar currentTime = Calendar.getInstance();
		currentTime.setTimeInMillis(System.currentTimeMillis());
		
		assertNotNull(mc.genCurrentStartPeriod());
		Calendar currentStartTime = Calendar.getInstance();
		currentStartTime.setTime(mc.genCurrentStartPeriod());
		assertTrue(currentTime.get(Calendar.DAY_OF_MONTH) == currentStartTime.get(Calendar.DAY_OF_MONTH));
		assertTrue(currentTime.get(Calendar.HOUR) == currentStartTime.get(Calendar.HOUR));
		assertTrue(currentTime.get(Calendar.MINUTE) == currentStartTime.get(Calendar.MINUTE));
		assertTrue(currentStartTime.get(Calendar.SECOND) == 0);
		assertTrue(currentStartTime.get(Calendar.MILLISECOND) == 0);
		assertNotNull(mc.genCurrentEndPeriod());
		
		Calendar currentEndTime = Calendar.getInstance();
		currentEndTime.setTime(mc.genCurrentEndPeriod());
		assertTrue(currentTime.get(Calendar.DAY_OF_MONTH) == currentEndTime.get(Calendar.DAY_OF_MONTH));
		assertTrue(currentTime.get(Calendar.HOUR) == currentEndTime.get(Calendar.HOUR));
		assertTrue(currentTime.get(Calendar.MINUTE) == currentEndTime.get(Calendar.MINUTE));
		assertTrue(currentEndTime.get(Calendar.SECOND) == 59);
		assertTrue(currentEndTime.get(Calendar.MILLISECOND) == 999);
				
		assertTrue(mc.getExpireTime() == (Long.parseLong(NonPersistentStatisticsConstants.DEFAULT_MINUTESTATISTICS_EXPIRETIME) * 1000));
		
		assertTrue(mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);
		
		mc.addEvent(getEvent());
		mc.addEvent(getEvent());
		assertTrue(mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 1);
		
		mc.flush();
		assertTrue(mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);		
	}
	
	public void testFifoQueue() throws Exception {
		MinuteStatisticsCollector mc = genMinuteStatisticsCollector("1");
		mc.addEvent(getEvent());
		assertTrue(mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 1);		
		Thread.sleep(1050);
		assertTrue(mc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);
		
	}
	
	/*
	public void testFifoQueue() throws Exception {
		MinuteStatisticsCollector mc = genMinuteStatisticsCollector("1");
		mc.addEvent(getEvent());
		mc.addEvent(getEvent());
		Thread.sleep(500);
		mc.addEvent(getEvent());
		assertTrue(mc.fetchStatistics(StatisticsConstants.TYPE_ALL, null, null).size() == 3);
		assertTrue(mc.fetchStatistics(StatisticsConstants.TYPE_ALL, new Date(System.currentTimeMillis() - 300), null).size() == 1);
		assertTrue(mc.fetchStatistics(StatisticsConstants.TYPE_ALL, new Date(System.currentTimeMillis() - 600), new Date(System.currentTimeMillis() - 500)).size() == 2);
		assertTrue(mc.fetchStatistics(StatisticsConstants.TYPE_ALL, null, new Date(System.currentTimeMillis() - 500)).size() == 2);
		
		Thread.sleep(550);
		assertTrue(mc.fetchStatistics(StatisticsConstants.TYPE_ALL, null, null).size() == 1);
	}*/
	
	
	private MinuteStatisticsCollector genMinuteStatisticsCollector(String expireTime){
		MinuteStatisticsCollector ret = new MinuteStatisticsCollector();		
		WorkerConfig config = new WorkerConfig();
		if(expireTime != null){
		  config.setProperty(NonPersistentStatisticsConstants.MINUTESTATISTICS_EXPIRETIME, expireTime);
		}
		ret.init(123, config, null);
		
		return ret;
	}

	private Event getEvent() throws InterruptedException{
		Event event = new Event(123);
		event.start();
		Thread.sleep(10);
		event.stop();
		return event;
	}
	
}
