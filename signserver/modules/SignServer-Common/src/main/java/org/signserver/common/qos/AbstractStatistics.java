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
package org.signserver.common.qos;

/**
 * Abstract statistics collector implementation for monitoring queue statistics
 * of QoS priority queues.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public abstract class AbstractStatistics {

    protected static AbstractStatistics instance;

    /**
     * Gets an instance of a concrete implementation of a
     * statistics collector.
     *
     * @return concrete instance of AbstractQoSFilterStatistics, if set, otherwise null
     */
    public synchronized static AbstractStatistics getDefaultInstance() {
        return instance;
    }

    /**
     * Sets a default singleton instance of AbstractQoSFilterStatistics.
     * This would be set by the web filter using its concrete implementation.
     *
     * @param instance to set
     */
    public synchronized static void setDefaultInstance(final AbstractStatistics instance) {
        AbstractStatistics.instance = instance;
    }
    
    /**
     * Sets a default instance if one has not already been set.
     * @param instance to set
     */
    public synchronized static void setDefaultInstanceIfUnset(final AbstractStatistics instance) {
        if (AbstractStatistics.instance == null) {
            AbstractStatistics.instance = instance;
        }
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
     * @param priorityLevel Priority level to get queue size for
     *                      (should be a value between 0 and getMaxPriorityLevel()
     *                       inclusive)
     * @return number of requests in the queue for the given priority level
     */
    public abstract int getQueueSizeForPriorityLevel(final int priorityLevel);

    /**
     * Get enabled status for QoS functionallity.
     *
     * @return enabled status
     */
    public abstract boolean isEnabled();

    /**
     * Get current number (estimate) of the number of threads waiting to
     * acquire the passes semaphore.
     *
     * @return Estimated number of waiting threads
     */
    public abstract int getSemaphoreQueueLength();
    
    /**
     * Get the current number of permits available in the passes semaphore.
     *
     * @return Number of permits available at this moment
     */
    public abstract int getSemaphoreAvailablePermits();
}
