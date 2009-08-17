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
import java.util.List;

import javax.persistence.EntityManager;

import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;

/**
 * A StatisticsCollector is in charge of
 * 
 * 
 * @author Philip Vendil 28 apr 2008
 *
 * @version $Id$
 */

public interface IStatisticsCollector {
	
	/**
	 * Method called  after instantiation.
	 * 
	 * @param workerId id of worker.
	 * @param config active worker configuration of worker
	 * @param em the SignServer EntityManager
	 * @throws SignServerException if unexpected error occurred during initialization.
	 */
	void init(int workerId, WorkerConfig config, EntityManager em) throws SignServerException;	
	
	/**
	 * Main method used to add an event to this StatisticsCollector. It is
	 * up to the implementation to decide how.
	 * 
	 * @param event the event to perform statistics on.
	 * @throws SignServerException if unexpected error occurred when collecting the statistics, such
	 * as DB failure or other IO problems.
	 */
	void addEvent(Event event) throws SignServerException;
	
	/**
	 * Signal to the Statistics Collector to flush all data and start again.
	 */
	void flush();
	
	/**
	 * Method used to fetch a list of StatisticsEntries maintained
	 * by the statistics collector.
	 * 
	 * @param type a defined String specifying what type of statistics
	 * that is requested. It's up to the implementation and the viewer of
	 * statistics to define the value of the type, but it should be unique.
	 * The value "ALL" should always return all statistics. Cannot be null. 
	 * @param startTime for statistics entries in the query, null gives no start time
	 * @param endTime for started statistics entries in the query, null gives no end time.
	 * @return A list of matching StatisticsEntry, never null.
	 */
	List<StatisticsEntry> fetchStatistics(String type, Date startTime, Date endTime);

}
