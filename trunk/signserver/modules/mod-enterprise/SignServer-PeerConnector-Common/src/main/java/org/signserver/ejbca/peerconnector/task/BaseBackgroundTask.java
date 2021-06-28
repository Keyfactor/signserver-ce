/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector.task;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Base implementation of a background task.
 * 
 * @version $Id$
 */
public abstract class BaseBackgroundTask implements BackgroundTask {

    private static final long serialVersionUID = 1L;
    private static final AtomicInteger idGenerator = new AtomicInteger(0);

    private final int id;
    private final String type;

    private boolean done = false;
    private boolean cancelled = false;
    private final long timeCreated = System.currentTimeMillis();
    private final long timeOfTimeOut;
    private String failureMessage = null;
    
    /** Constructor when we want to define the id in the caller */
    protected BaseBackgroundTask(final String type, final long timeOutMs, final int id) {
        if (timeOutMs==Long.MAX_VALUE) {
            this.timeOfTimeOut = Long.MAX_VALUE;
        } else {
            this.timeOfTimeOut = timeCreated + timeOutMs;
        }
        this.id = id;
        this.type = type;
    }

    /** Constructor when we want to an auto-generated id */
    protected BaseBackgroundTask(final String type, final long timeOutMs) {
        if (timeOutMs==Long.MAX_VALUE) {
            this.timeOfTimeOut = Long.MAX_VALUE;
        } else {
            this.timeOfTimeOut = timeCreated + timeOutMs;
        }
        this.id = idGenerator.getAndIncrement();
        this.type = type;
    }

    protected boolean isStopRequested() { return isCancelled() || isTimedOut(); }
    private boolean isTimedOut() { return System.currentTimeMillis()>timeOfTimeOut; }

    protected void setFailureMessage(final String failureMessage) { this.failureMessage = failureMessage; }
    protected void setDone(final boolean done) { this.done=done ; }

    @Override
    public boolean isDone() { return done; }
    @Override
    public boolean isCancelled() { return cancelled; }
    @Override
    public String getType() { return type; }
    @Override
    public int getId() { return id; }
    @Override
    public long getTimeCreated() { return timeCreated; }
    @Override
    public abstract void run();
    @Override
    public void cancel() { cancelled=true; }
    @Override
    public String getFailureMessage() { return failureMessage; }
}
