package org.signserver.test.performance.impl;

import java.util.Date;
import java.util.Random;

import org.apache.log4j.Logger;
import org.signserver.test.performance.FailureCallback;
import org.signserver.test.performance.WorkerThread;
import org.signserver.test.performance.FailedException;

public class TimeStampThread extends WorkerThread {
    /** Logger for this class */
    Logger LOG = Logger.getLogger(TimeStampThread.class);

    private int maxWaitTime;
    private TimeStamp tsa;
    private Random random;
    private long startTime;
    private long warmupTime;
    
    public TimeStampThread(final String name, final FailureCallback failureCallback, final String url, int maxWaitTime,
    		int seed, long warmupTime) {
        super(name, failureCallback);
        this.maxWaitTime = maxWaitTime;
        this.random = new Random(seed);
        this.tsa = new TimeStamp(url, random);
        this.warmupTime = warmupTime;
    }

    @Override
    public void run() {
        startTime = (new Date()).getTime();
        
        try {
            while (!isStop()) {
            	long currentTime = (new Date().getTime());
                long estimatedTime;
                
                try {
                    estimatedTime = tsa.run();
                } catch (FailedException ex) {
                    fireFailure("THREAD" + getName() + " failed after " + getOperationsPerformed() + " signings: " + ex.getMessage());
                    break;
                }
              
                if (currentTime > startTime + warmupTime) {
                    addResponseTime(estimatedTime);
                    increaseOperationsPerformed();
                }
                
                // Sleep
                Thread.sleep((int) (random.nextDouble() * maxWaitTime));
            }
        } catch (InterruptedException ex) {
            LOG.error("Interrupted: " + ex.getMessage());
        }
    }
    
}
