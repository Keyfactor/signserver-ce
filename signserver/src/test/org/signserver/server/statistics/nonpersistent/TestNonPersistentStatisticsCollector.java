package org.signserver.server.statistics.nonpersistent;

import java.util.List;

import junit.framework.TestCase;

import org.signserver.common.NonPersistentStatisticsConstants;
import org.signserver.common.StatisticsConstants;
import org.signserver.common.WorkerConfig;
import org.signserver.server.statistics.Event;
import org.signserver.server.statistics.StatisticsEntry;

public class TestNonPersistentStatisticsCollector extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
	}
	
	public void testBasics() throws Exception {
		NonPersistantStatisticsCollector nc = genNonPersistantStatisticsCollector(null,null,null,null);
					
		assertTrue(nc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);
		
		nc.addEvent(getEvent());
		nc.addEvent(getEvent());
		Thread.sleep(1050);
		nc.addEvent(getEvent());
		List<StatisticsEntry> list = nc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null);
		assertTrue(list.size() == 5);
		
		list = nc.fetchStatistics(NonPersistentStatisticsConstants.QUERYTYPE_SECOND, null, null);
		assertTrue(list.size() == 2);		
		assertTrue(list.get(0).getNumberOfEvents() == 2);
		assertTrue(list.get(1).getNumberOfEvents() == 1);

		list = nc.fetchStatistics(NonPersistentStatisticsConstants.QUERYTYPE_MINUTE, null, null);
		assertTrue(list.size() == 1);		
		assertTrue(list.get(0).getNumberOfEvents() == 3);

		list = nc.fetchStatistics(NonPersistentStatisticsConstants.QUERYTYPE_HOUR, null, null);
		assertTrue(list.size() == 1);		
		assertTrue(list.get(0).getNumberOfEvents() == 3);

		list = nc.fetchStatistics(NonPersistentStatisticsConstants.QUERYTYPE_DAY, null, null);
		assertTrue(list.size() == 1);		
		assertTrue(list.get(0).getNumberOfEvents() == 3);
		
		nc.flush();
		assertTrue(nc.fetchStatistics(StatisticsConstants.QUERYTYPE_ALL, null, null).size() == 0);
				
	}

	
	private NonPersistantStatisticsCollector genNonPersistantStatisticsCollector(String secondExpireTime,
			                                                                     String minuteExpireTime,
			                                                                     String hourExpireTime,
			                                                                     String dayExpireTime) throws Exception{
		NonPersistantStatisticsCollector ret = new NonPersistantStatisticsCollector();		
		WorkerConfig config = new WorkerConfig();
		if(secondExpireTime != null){
		   config.setProperty(NonPersistentStatisticsConstants.SECONDSTATISTICS_EXPIRETIME, secondExpireTime);
		}
		if(minuteExpireTime != null){
		  config.setProperty(NonPersistentStatisticsConstants.MINUTESTATISTICS_EXPIRETIME, minuteExpireTime);
		}
		if(hourExpireTime != null){
		  config.setProperty(NonPersistentStatisticsConstants.HOURSTATISTICS_EXPIRETIME, hourExpireTime);
		}
		if(dayExpireTime != null){
		  config.setProperty(NonPersistentStatisticsConstants.DAYSTATISTICS_EXPIRETIME, dayExpireTime);
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
