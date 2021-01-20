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
package org.signserver.web.common.filters;

/**
 * A constant class concentrating constants for QoSFiler. Some of constants are pointing to names of a Global property.
 *
 * @author Andrey Sergeev 18-jan-2021
 * @version $Id$
 */
public class QoSFilterProperties {

    /**
     * Global property - enables/disables QoS Filter.
     */
    public static final String QOS_FILTER_ENABLED = "QOS_FILTER_ENABLED";
    /**
     * Global property - defines the
     */
    public static final String QOS_PRIORITIES = "QOS_PRIORITIES";
    /**
     * Global property - defines the number of maximum requests per a priority.
     */
    public static final String QOS_MAX_REQUESTS = "QOS_MAX_REQUESTS";
    /**
     * Global property - defines the maximum priority of QoS Filter.
     */
    public static final String QOS_MAX_PRIORITY = "QOS_MAX_PRIORITY";
    /**
     * Global property - defines the amount of seconds to keep cache.
     */
    public static final String QOS_CACHE_TTL_S = "QOS_CACHE_TTL_S";
    /**
     * Defines an attribute to keep the priority, whether within a request forwarding or in audit logs.
     */
    public static final String QOS_PRIORITY = "QOS_PRIORITY";
}
