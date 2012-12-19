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
package org.signserver.test.performance;

import org.signserver.test.performance.FailureCallback;

/**
 * Thread running tests.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class WorkerThread extends Thread {
    private final FailureCallback failureCallback;
    private volatile boolean stop;
    
    protected long operationsPerformed;
    
    public WorkerThread(final String name, final FailureCallback failureCallback) {
        super(name);
        this.failureCallback = failureCallback;
    }

    /**
     * Indicate that this thread has discovered a failure.
     * @param message A description of the problem
     */
    protected void fireFailure(final String message) {
        failureCallback.failed(this, message);
    }
    
    /**
     * Indicate that this tried should stop at next possible moment.
     */
    public void stopIt() {
        stop = true;
    }

    /**
     * @return Wither this thread should stop or not.
     */
    public boolean isStop() {
        return stop;
    }
    
    /**
     * Increases the counter for number of operations performed.
     */
    protected void increaseOperationsPerformed() {
        operationsPerformed++;
    }
    
    /**
     * @return The number of operations this thread has performed.
     */
    public long getOperationsPerformed() {
        return operationsPerformed;
    }
}
