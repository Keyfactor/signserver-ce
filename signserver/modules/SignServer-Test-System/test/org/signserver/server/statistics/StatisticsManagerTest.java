package org.signserver.server.statistics;

import org.signserver.common.SignServerException;
import org.signserver.common.StatisticsConstants;
import org.signserver.common.WorkerConfig;

import junit.framework.TestCase;

public class StatisticsManagerTest extends TestCase {

	protected void setUp() throws Exception {
		super.setUp();
	}

	public void testAll() throws SignServerException {
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
