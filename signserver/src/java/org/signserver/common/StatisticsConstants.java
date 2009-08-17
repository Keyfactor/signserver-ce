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
package org.signserver.common;

/**
 * Class containing constants common for all statistics configuration of the SignServer.
 * 
 * @author Philip Vendil
 */
public class StatisticsConstants {
	
	/**
	 * Worker property indicating if statistics should be used and in that what type of statistics.
	 * Can have either one of the StatisticsConstants.TYPE_ constants or the class path of a statistics
	 * collector implementing the IStatisticsCollector interface.
	 * 
	 * If this property isn't set for a worker will no statistics be done.
	 */
	public static final String TYPE = "STATISTICS.TYPE";
	
	/**
	 * Help value used instead of class path to indicate that the non persistant statistics should
	 * be used.
	 */
	public static final String TYPE_NONPERSISTANT = "NONPERSISTANT";
	/**
	 * Help value used instead of class path to indicate that CVS file writer statistics should
	 * be used.
	 */
	public static final String TYPE_CSVFILEWRITER = "CSVFILEWRITER";
	
	/**
	 * Type constant indicating that all types of statistics should be returned
	 * in the query.
	 */
	public static final String QUERYTYPE_ALL = "ALL";
 
}
