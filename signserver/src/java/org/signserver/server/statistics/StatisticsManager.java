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

import java.util.HashMap;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.SignServerException;
import org.signserver.common.StatisticsConstants;
import org.signserver.common.WorkerConfig;
import org.signserver.server.statistics.csvfilewriter.CSVFileStatisticsCollector;
import org.signserver.server.statistics.nonpersistent.NonPersistantStatisticsCollector;

/**
 * Class managing all statistics instances.
 * 
 * The methods are startEvent and endEvent, startEvent that creates and maintains
 * a statistics collector for a worker if it's configured to do so, and endEvent
 * managing the storage of that event.
 * 
 * 
 * @author Philip Vendil 9 maj 2008
 *
 * @version $Id$
 */

public class StatisticsManager {
	private static final Logger log = Logger.getLogger(StatisticsManager.class);	

	private static HashMap<Integer,IStatisticsCollector> instances = new HashMap<Integer,IStatisticsCollector>();
	
	/**
	 * Method used to signal to the StatisticsManager to create a statistics event using the
	 * configure statistics manager.
	 * 
	 * @param workerId id of the worker calling
	 * @param config the active configuration of the worker
	 * @param em the EntityManager used by the worker.
	 * @return an Event if statistics is going to be used or null if statistics is disabled.
	 */
	 public static  Event startEvent(int workerId, WorkerConfig config, EntityManager em){
		Event retval = null;
		IStatisticsCollector sc = getStatisticsCollector(workerId,config,em);
		if(sc != null){			
			retval = new Event(workerId);
			retval.start();
		}
		return retval;		 
	}

	/**
	 * Method signaling that the given event has ended and should be stored in the configure
	 * statistics collector. 
	 * 
	 * @param workerId id of the worker calling
	 * @param config the active configuration of the worker
	 * @param em the EntityManager used by the worker.
	 * @param event the event created by the startEvent method.
	 * @throws SignServerException if unexpected error occurred when collecting the statistics, such
	 * as DB failure or other IO problems.
	 */
	public static void endEvent(int workerId, WorkerConfig config, EntityManager em, Event event) throws SignServerException{
		if(event != null){
			event.stop();
			IStatisticsCollector sc = getStatisticsCollector(workerId,config,em);
			if(sc != null){			
				sc.addEvent(event);
			}
		}
	}
	
	/**
	 * Method in charge of creating and maintaining an workers statistics collector.
	 * @param workerId 
	 * @param config the active worker configuration
	 */
	public static IStatisticsCollector getStatisticsCollector(int workerId,
			WorkerConfig config, EntityManager em) {
		if(config.getProperty(StatisticsConstants.TYPE) == null){
			return null;
		}
		
		if(instances.get(workerId) != null){
			return instances.get(workerId);
		}		
		
		return genStatisticsCollector(workerId,
				config, em);

	}

	private synchronized static IStatisticsCollector genStatisticsCollector(int workerId,
			WorkerConfig config, EntityManager em) {

		String typeValue = config.getProperty(StatisticsConstants.TYPE);

		String classPath = null;
		if(typeValue.equalsIgnoreCase(StatisticsConstants.TYPE_NONPERSISTANT)){
			classPath = NonPersistantStatisticsCollector.class.getName();
		}
		if(typeValue.equalsIgnoreCase(StatisticsConstants.TYPE_CSVFILEWRITER)){
			classPath = CSVFileStatisticsCollector.class.getName();
		}

		if(classPath == null){
			classPath = typeValue;
		}

		try{
			IStatisticsCollector sc = (IStatisticsCollector) StatisticsManager.class.getClassLoader().loadClass(classPath).newInstance();
			sc.init(workerId, config, em);
			instances.put(workerId, sc);
			return sc;
		}catch(Exception e){
			log.error("Error generating statistics for worker with id " + workerId + " check that the worker property " + StatisticsConstants.TYPE + " is configured propertly. It currently have the value '" + typeValue + " the error was of type " + e.getClass().getName() + " and had the following message : " + e.getMessage() + ". Statistics will be disabled until next reload.");
			log.debug("Stacktrace :", e);
		}	
		return null;
	}

	/**
	 * resets the statistics of the given workerId
	 * @param workerId of worker to reset statistics for or '0' for all workers.
	 */
	public static void flush(int workerId){
		if(workerId == 0){
			instances.clear();
		}else{
			instances.remove(workerId);
		}
	}
}
