/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.server.enterprise.web.filters;

import org.signserver.common.RequestContext;

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
    public static final String QOS_PRIORITY = RequestContext.QOS_PRIORITY;
}
