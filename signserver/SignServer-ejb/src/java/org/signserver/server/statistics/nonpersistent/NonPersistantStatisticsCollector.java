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

import java.util.Date;
import java.util.List;

import javax.persistence.EntityManager;

import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.statistics.Event;
import org.signserver.server.statistics.IStatisticsCollector;
import org.signserver.server.statistics.StatisticsEntry;

/**
 * The main statistics collector used keep statistics
 * on second, minute, hour and day level, mainly to be used
 * for a Windows "task manager" like  display of the 
 * load of the current worker. 
 * 
 * 
 * @author Philip Vendil 6 maj 2008
 *
 */

public class NonPersistantStatisticsCollector implements IStatisticsCollector{

	private SecondStatisticsCollector secondStatisticsCollector = new SecondStatisticsCollector();
	private MinuteStatisticsCollector minuteStatisticsCollector = new MinuteStatisticsCollector();
	private HourStatisticsCollector hourStatisticsCollector = new HourStatisticsCollector();
	private DayStatisticsCollector dayStatisticsCollector = new DayStatisticsCollector();
	
	public void init(int workerId, WorkerConfig config, EntityManager em) throws SignServerException {
       secondStatisticsCollector.init(workerId, config, em);
	   minuteStatisticsCollector.init(workerId, config, em);
       hourStatisticsCollector.init(workerId, config, em);
       dayStatisticsCollector.init(workerId, config, em);
    }
	
	public void addEvent(Event event) throws SignServerException {
		if(secondStatisticsCollector.getExpireTime() != 0){
			secondStatisticsCollector.addEvent(event);
		}
		if(minuteStatisticsCollector.getExpireTime() != 0){
			minuteStatisticsCollector.addEvent(event);
		}
		if(hourStatisticsCollector.getExpireTime() != 0){
			hourStatisticsCollector.addEvent(event);
		}
		if(dayStatisticsCollector.getExpireTime() != 0){
			dayStatisticsCollector.addEvent(event);
		}
	}

	public List<StatisticsEntry> fetchStatistics(String type, Date startTime,
			Date endTime) {
		List<StatisticsEntry> retval = secondStatisticsCollector.fetchStatistics(type, startTime, endTime);
		retval.addAll(minuteStatisticsCollector.fetchStatistics(type, startTime, endTime));
		retval.addAll(hourStatisticsCollector.fetchStatistics(type, startTime, endTime));
		retval.addAll(dayStatisticsCollector.fetchStatistics(type, startTime, endTime));
		return retval;
	}

	public void flush() {
		secondStatisticsCollector.flush();
		minuteStatisticsCollector.flush();
		hourStatisticsCollector.flush();
		dayStatisticsCollector.flush();
	}



}
