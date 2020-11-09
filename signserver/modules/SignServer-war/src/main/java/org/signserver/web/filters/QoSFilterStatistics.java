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

import org.signserver.common.AbstractQoSFilterStatistics;

/**
 * Statistics collector for the QoSFilter web filter.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class QoSFilterStatistics extends AbstractQoSFilterStatistics {

    private final QoSFilter filter;

    public QoSFilterStatistics(final QoSFilter filter) {
        this.filter = filter;
        instance = this;
    }

    @Override
    public int getQueueSizeForPriorityLevel(int priorityLevel) {
        return filter.getQueueSizeForPriorityLevel(priorityLevel);
    }

    @Override
    public int getMaxPriorityLevel() {
        return filter.getMaxPriorityLevel();
    }
}
