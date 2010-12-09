package org.signserver.server.statistics.nonpersistent;

import java.util.Calendar;
import java.util.List;

import junit.framework.TestCase;

import org.signserver.common.NonPersistentStatisticsConstants;
import org.signserver.common.StatisticsConstants;
import org.signserver.common.WorkerConfig;
import org.signserver.server.statistics.Event;
import org.signserver.server.statistics.StatisticsEntry;

public class DayStatisticsCollectorTest extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
	}
	
	public void testBasics() throws Exception {
		DayStatisticsCollector dc = genDayStatisticsCollector(null);
		
		Calendar currentTime = Calendar.getInstance();
		currentTime.setTimeInMillis(System.currentTimeMillis());
				
		assertNotNull(dc.genCurrentStartPeriod());
		Calendar currentStartTime = Calendar.getInstance();
		currentStartTime.setTime(dc.genCurrentStartPeriod());
		assertTrue(currentTime.get(Calendar.DAY_OF_MONTH) == currentStartTime.get(Calendar.DAY_OF_MONTH));
		assertTrue(currentStartTime.get(Calendar.HOUR) == 0);
		assertTrue(currentStartTime.get(Calendar.MINUTE) == 0);
		assertTrue(currentStartTime.get(Calendar.SECOND) == 0);
		assertTrue(currentStartTime.get(Calendar.MILLISECOND) == 0);
		
		assertNotNull(dc.genCurrentEndPeriod());
		Calendar currentEndTime = Calendar.getInstance();
		currentEndTime.setTime(dc.genCurrentEndPeriod());
		assertTrue(currentTime.get(Calendar.DAY_OF_MONTH) == currentEndTime.get(Calendar.DAY_OF_MONTH));
		assertTrue(currentEndTime.get(Calendar.HOUR_OF_DAY) == 23);
		assertTrue(currentEndTime.get(Calendar.HOUR) == 11);
		assertTrue(currentEndTime.get(Calendar.MINUTE) == 59);
		assertTrue(currentEndTime.get(Calendar.SECOND) == 59);
		assertTrue(currentEndTime.get(Calendar.MILLISECOND) == 999);
		assertTrue(""+dc.getExpireTime(), dc.getExpireTime() == (Long.parseLong(NonPersistentStatisticsConstants.DEFAULT_DAYSTATISTICS_EXPIRETIME) * 1000));
		
		assertTrue(dc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);
		
		dc.addEvent(getEvent());
		dc.addEvent(getEvent());
		List<StatisticsEntry> list = dc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null);
		assertTrue(list.size() == 1);
		assertTrue(list.get(0).getNumberOfEvents() == 2);
		
		dc.flush();
		assertTrue(dc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);		
	}
	
	public void testFifoQueue() throws Exception {
		DayStatisticsCollector hc = genDayStatisticsCollector("1");
		hc.addEvent(getEvent());
		assertTrue(hc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 1);		
		Thread.sleep(1050);
		assertTrue(hc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);
		
	}
	
	
	private DayStatisticsCollector genDayStatisticsCollector(String expireTime){
		DayStatisticsCollector ret = new DayStatisticsCollector();		
		WorkerConfig config = new WorkerConfig();
		if(expireTime != null){
		  config.setProperty(NonPersistentStatisticsConstants.DAYSTATISTICS_EXPIRETIME, expireTime);
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
