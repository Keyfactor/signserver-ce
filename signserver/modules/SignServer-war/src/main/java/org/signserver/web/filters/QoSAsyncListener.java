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
package org.signserver.web.filters;

import java.io.IOException;
import javax.servlet.AsyncContext;
import javax.servlet.AsyncEvent;
import javax.servlet.AsyncListener;
import javax.servlet.http.HttpServletResponse;

/**
 * Refactored-out from QoSFilter.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
class QoSAsyncListener implements AsyncListener {
    
    private final int priority;
    private final QoSFilter outer;

    public QoSAsyncListener() {
        this.outer = null;
        this.priority = -1;
    }
    
    public QoSAsyncListener(final QoSFilter outer) {
        this.outer = outer;
        this.priority = -1;
    }

    public QoSAsyncListener(int priority, final QoSFilter outer) {
        this.outer = outer;
        this.priority = priority;
    }

    @Override
    public void onStartAsync(AsyncEvent event) throws IOException {
    }

    @Override
    public void onComplete(AsyncEvent event) throws IOException {
    }

    @Override
    public void onTimeout(AsyncEvent event) throws IOException {
        // Remove before it's redispatched, so it won't be
        // redispatched again at the end of the filtering.
        AsyncContext asyncContext = event.getAsyncContext();
        outer.getQueues()[priority].remove(asyncContext);
        ((HttpServletResponse) event.getSuppliedResponse()).sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        asyncContext.complete();
    }

    @Override
    public void onError(AsyncEvent event) throws IOException {
    }
    
}
