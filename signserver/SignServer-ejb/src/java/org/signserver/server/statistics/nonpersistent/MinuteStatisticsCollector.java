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

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.signserver.common.NonPersistentStatisticsConstants;
import org.signserver.common.StatisticsConstants;
import org.signserver.server.statistics.StatisticsEntry;

/**
 * Class in charge on maintaining statistics for all events
 * that have happened the last minute.
 * 
 * 
 * @author Philip Vendil 28 apr 2008
 *
 * @version $Id$
 */

public class MinuteStatisticsCollector extends BaseFIFOStatisticsCollector{
	
	private transient Logger log = Logger.getLogger(this.getClass());



	@Override
	protected Date genCurrentStartPeriod() {		
		Calendar cal = Calendar.getInstance();
		cal.set(Calendar.SECOND, 0);
		cal.set(Calendar.MILLISECOND, 0);
		return cal.getTime();
	}
	
	@Override
	protected Date genCurrentEndPeriod() {
		Calendar cal = Calendar.getInstance();				
		cal.set(Calendar.SECOND, 59);
		cal.set(Calendar.MILLISECOND, 999);
		return cal.getTime();
	}


	public List<StatisticsEntry> fetchStatistics(String type, Date startTime,
			Date endTime) {
		List<StatisticsEntry> retval;
		if(type.equals(StatisticsConstants.QUERYTYPE_ALL) || type.equals(NonPersistentStatisticsConstants.QUERYTYPE_MINUTE)){
			retval = fetchStatistics(startTime,endTime);
		}else{
			retval = new ArrayList<StatisticsEntry>();
		}
		return retval;
	}

	@Override	
	public long getExpireTime() {
		return getExpireTime(NonPersistentStatisticsConstants.MINUTESTATISTICS_EXPIRETIME, NonPersistentStatisticsConstants.DEFAULT_MINUTESTATISTICS_EXPIRETIME, log);		
	}

}
