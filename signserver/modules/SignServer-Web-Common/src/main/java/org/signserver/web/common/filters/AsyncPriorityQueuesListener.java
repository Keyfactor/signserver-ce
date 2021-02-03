//
// ========================================================================
// Copyright (c) 1995-2020 Mort Bay Consulting Pty Ltd and others.
//
// This program and the accompanying materials are made available under
// the terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0
//
// This Source Code may also be made available under the following
// Secondary Licenses when the conditions for such availability set
// forth in the Eclipse Public License, v. 2.0 are satisfied:
// the Apache License v2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
// ========================================================================
//
package org.signserver.web.common.filters;

import java.io.IOException;
import javax.servlet.AsyncContext;
import javax.servlet.AsyncEvent;
import javax.servlet.AsyncListener;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;

/**
 * Refactored-out from QoSFilter.
 * <p>
 * To be able to deploy the filter on JBoss/WildFly we had to move the listener to an outer-level class with a
 * public constructor (and make adjustments to the filter class to access its priority queues).
 * </p><p>
 * Error message: WFLYEE0048: Could not find default contructor for class
 * org.signserver.web.filter.QoSFilter$QoSAsyncListener
 * </p>
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
class AsyncPriorityQueuesListener implements AsyncListener {

    // Logger for this class
    private static final Logger LOG = Logger.getLogger(AsyncPriorityQueuesListener.class);

    private final int priority;
    private final QoSFilter qoSFilter;

    public AsyncPriorityQueuesListener() {
        this.qoSFilter = null;
        this.priority = -1;
    }

    public AsyncPriorityQueuesListener(final QoSFilter qoSFilter) {
        this.qoSFilter = qoSFilter;
        this.priority = -1;
    }

    public AsyncPriorityQueuesListener(int priority, final QoSFilter qoSFilter) {
        this.qoSFilter = qoSFilter;
        this.priority = priority;
    }

    @Override
    public void onStartAsync(AsyncEvent event) {
    }

    @Override
    public void onComplete(AsyncEvent event) {
        // Note: This is different from the original QoSFilter.
        // As it turned out the original filter (when running on WildFly at least) did not call the filter again after
        // asyncContext.dispatch() and thus the queues are only processed when there is a new request coming in and
        // which is accepted. This means that it could happen that requests gets stuck in the queue if no more requests
        // are coming in. Instead poll the first entry from the first queue now.
        // Note that this does not require a pass so it needs to be investigated if this could lead to too many requests
        // being served at the same time (?).
        qoSFilter.processQueues();
    }

    @Override
    public void onTimeout(AsyncEvent event) throws IOException {
        // Remove before it's redispatched, so it won't be redispatched again at the end of the filtering.
        final AsyncContext asyncContext = event.getAsyncContext();
        if (qoSFilter == null) {
            LOG.error("Filter unavailable");
        } else {
            qoSFilter.removeFromQueue(asyncContext, priority);
        }
        ((HttpServletResponse) event.getSuppliedResponse()).sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        asyncContext.complete();
    }

    @Override
    public void onError(AsyncEvent event) {
    }

}
