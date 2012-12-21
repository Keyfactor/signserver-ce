package org.signserver.test.performance.impl;

import java.util.Date;
import java.util.Random;

import org.apache.log4j.Logger;
import org.signserver.ejb.interfaces.IWorkerSession;
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
                // current time
                long timeBefore = (new Date()).getTime();
                
                try {
                    tsa.run();
                } catch (FailedException ex) {
                    fireFailure("THREAD" + getName() + " failed after " + getOperationsPerformed() + " signings: " + ex.getMessage());
                    break;
                }
                
                long timeAfter = (new Date()).getTime();
                
                if (timeBefore > startTime + warmupTime) {
                    addResponseTime(timeAfter - timeBefore);
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
