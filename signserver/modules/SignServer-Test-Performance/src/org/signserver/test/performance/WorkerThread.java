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

import java.util.ArrayList;
import java.util.Collection;
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
    protected Collection<Long> respTimes;

    
    public WorkerThread(final String name, final FailureCallback failureCallback) {
        super(name);
        this.failureCallback = failureCallback;
        this.respTimes = new ArrayList<Long>();
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
    
    /**
     * Add response time to statistics list.
     * @param time
     */
    public void addResponseTime(long time) {
        respTimes.add(time);
    }
    
    /**
     * Get average response time.
     * @return Average response time
     */
    public double getAverageResponseTime() {
        long sum = 0;
        
        for (long time : respTimes) {
            sum += time;
        }
        
        return (double) sum / respTimes.size();
    }
    
    /**
     * Get maximum response time.
     * @return Maximum response time
     */
    public long getMaxResponseTime() {
        long max = 0;
        
        for (long time : respTimes) {
            if (time > max) {
                max = time;
            }
        }
        
        return max;
    }
    
    /**
     * Get minimum response time.
     * @return Minimum response time
     */
    public long getMinResponseTime() {
        long min = Long.MAX_VALUE;
        
        for (long time : respTimes) {
            if (time < min) {
                min = time;
            }
        }
        
        return min;
    }
    
    /**
     * Get standard deviation of response time.
     * Uses the formula from {@link http://en.wikipedia.org/wiki/Standard_deviation}
     * 
     * @return Standard deviation
     */
    public double getStdDevResponseTime() {
        double avg = getAverageResponseTime();
        double sqrSum = 0;
        
        for (long time : respTimes) {
            double diffSqr = (time - avg) * (time - avg);
            
            sqrSum += diffSqr;
        }
        
        return Math.sqrt(sqrSum / respTimes.size());
    }
}
