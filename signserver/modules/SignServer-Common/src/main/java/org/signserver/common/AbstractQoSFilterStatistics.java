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
 * Statistics collector for the QoS web filter.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public abstract class AbstractQoSFilterStatistics {

    protected static AbstractQoSFilterStatistics instance;

    /**
     * Gets an instance of a concrete implementation of a
     * statistics collector.
     *
     * @return concrete instance of AbstractQoSFilterStatistics, if set, otherwise null
     */
    public static AbstractQoSFilterStatistics getDefaultInstance() {
        return instance;
    }

    /**
     * Sets a default singleton instance of AbstractQoSFilterStatistics.
     * This would be set by the web filter using its concrete implementation.
     *
     * @param instance 
     */
    public static void setDefaultInstance(final AbstractQoSFilterStatistics instance) {
        AbstractQoSFilterStatistics.instance = instance;
    }

    /**
     * Get maximum priority level configured in web filter.
     *
     * @return maximum priority level
     */
    public abstract int getMaxPriorityLevel();

    /**
     * Get the maximum number of requests handled concurrently by filter
     * before placing request in priority queues.
     *
     * @return maximum number of requests
     */
    public abstract int getMaxRequests();

    /**
     * Get current number of queued requests at a given priority level.
     *
     * @param priorityLevel
     * @return number of requests in the queue for the given priority level
     */
    public abstract int getQueueSizeForPriorityLevel(final int priorityLevel);

    /**
     * Get enabled status of the QoS web filter.
     *
     * @return enabled status
     */
    public abstract boolean getFilterEnabled();
}
