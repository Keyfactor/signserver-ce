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
package org.signserver.web.filters;

import org.signserver.common.qos.AbstractStatistics;

/**
 * Implementation of the abstract QoS statistics collector interfacing
 * with the instance of the QoS web filter.
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
    public boolean getFilterEnabled() {
        return filter.getFilterEnabled();
    }
}
