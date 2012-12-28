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

import org.apache.log4j.Logger;

/**
 * Thread running tests.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class WorkerThread extends Thread {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(WorkerThread.class);
    
    private final FailureCallback failureCallback;
    private volatile boolean stop;
    
    protected long operationsPerformed;
    protected long respTimesSum;
    protected long maxRespTime;
    protected long minRespTime = Long.MAX_VALUE;

    
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
     * @return The number of operations this thread has performed.
     */
    public long getOperationsPerformed() {
        return operationsPerformed;
    }
    
    /**
     * Add response time to statistics and increase number of operations.
     * @param time the response time
     */
    public void addResponseTime(long time) {
        operationsPerformed++;
        respTimesSum += time;
        if (time > maxRespTime) {
            maxRespTime = time;
        }
        if (time < minRespTime) {
            minRespTime = time;
        }
    }
    
    /**
     * Get average response time.
     * @return Average response time
     */
    public double getAverageResponseTime() {
        return (double) respTimesSum / operationsPerformed;
    }
    
    /**
     * @return Sum of all response times
     */
    public long getResponseTimeSum() {
        return respTimesSum;
    }
    
    /**
     * Get maximum response time.
     * @return Maximum response time
     */
    public long getMaxResponseTime() {
        return maxRespTime;
    }
    
    /**
     * Get minimum response time.
     * @return Minimum response time
     */
    public long getMinResponseTime() {
        return minRespTime;
    }
    
}
