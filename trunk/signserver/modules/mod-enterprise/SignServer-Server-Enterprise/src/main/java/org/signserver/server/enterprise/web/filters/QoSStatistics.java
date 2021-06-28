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

/**
 * Implementation of the abstract QoS statistics collector interfacing with the instance of the QoS web filter.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class QoSStatistics extends AbstractStatistics {

    private final QoSFilter filter;

    public QoSStatistics(final QoSFilter filter) {
        this.filter = filter;
    }

    @Override
    public int getQueueSizeForPriorityLevel(int priorityLevel) {
        return filter.getQueueSizeForPriorityLevel(priorityLevel);
    }

    @Override
    public int getMaxPriorityLevel() {
        return filter.getMaxPriorityLevel();
    }

    @Override
    public int getMaxRequests() {
        return filter.getMaxRequests();
    }

    @Override
    public boolean isEnabled() {
        return filter.isFilterEnabled();
    }

    @Override
    public int getSemaphoreQueueLength() {
        return filter.getSemaphoreQueueLength();
    }

    @Override
    public int getSemaphoreAvailablePermits() {
        return filter.getSemaphoreAvailablePermits();
    }
}
