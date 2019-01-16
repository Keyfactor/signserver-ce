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
 * Class containing constants common for the non persistent statistics configuration of the SignServer.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class NonPersistentStatisticsConstants {

    /**
     * Type constant indicating that only second statistics should be returned
     * in the query.
     */
    public static final String QUERYTYPE_SECOND = "SECOND";
    
    /**
     * Type constant indicating that only minute statistics should be returned
     * in the query.
     */
    public static final String QUERYTYPE_MINUTE = "MINUTE";
    
    /**
     * Type constant indicating that only hour statistics should be returned
     * in the query.
     */
    public static final String QUERYTYPE_HOUR = "HOUR";
    
    /**
     * Type constant indicating that only day statistics should be returned
     * in the query.
     */
    public static final String QUERYTYPE_DAY = "DAY";
    
    /**
     * Setting indicating the expire time of how long a second statistics collector
     * should save an statistics entry before it is expired and removed.
     * 
     * Default is 60 seconds, 0 means no seconds statistics should be kept.
     */
    public static final String SECONDSTATISTICS_EXPIRETIME = "STATISTICS.SECONDSTATISTICS.EXPIRETIME";
    public static final String DEFAULT_SECONDSTATISTICS_EXPIRETIME = "60";

    /**
     * Setting indicating the expire time of how long a minute statistics collector
     * should save an statistics entry before it is expired and removed.
     * 
     * Default is 900 seconds (15 minutes), 0 means no minute statistics should be kept.
     */
    public static final String MINUTESTATISTICS_EXPIRETIME = "STATISTICS.MINUTESTATISTICS.EXPIRETIME";
    public static final String DEFAULT_MINUTESTATISTICS_EXPIRETIME = "900";
    
    /**
     * Setting indicating the expire time of how long a hour statistics collector
     * should save an statistics entry before it is expired and removed.
     * 
     * Default is 86400 seconds (one day), 0 means no hour statistics should be kept.
     */
    public static final String HOURSTATISTICS_EXPIRETIME = "STATISTICS.HOURSTATISTICS.EXPIRETIME";
    public static final String DEFAULT_HOURSTATISTICS_EXPIRETIME = "86400";
    
    /**
     * Setting indicating the expire time of how long a hour statistics collector
     * should save an statistics entry before it is expired and removed.
     * 
     * Default is 2592000 seconds (30 days), 0 means no day statistics should be kept.
     */
    public static final String DAYSTATISTICS_EXPIRETIME = "STATISTICS.DAYSTATISTICS.EXPIRETIME";
    public static final String DEFAULT_DAYSTATISTICS_EXPIRETIME = "2592000";
}
