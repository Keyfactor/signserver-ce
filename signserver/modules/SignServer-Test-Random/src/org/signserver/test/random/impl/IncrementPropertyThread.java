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
package org.signserver.test.random.impl;

import java.util.Random;
import org.apache.log4j.Logger;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.test.random.FailureCallback;
import org.signserver.test.random.WorkerThread;

/**
 * Increments a property value and for every 10 iteration checks that the actual 
 * value equals the expected value.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class IncrementPropertyThread extends WorkerThread {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(IncrementPropertyThread.class);
    private final int workerId;
    private final String property;
    private final IWorkerSession.IRemote workerSession;
    private final Random random;
    private final IncrementProperty increment;

    public IncrementPropertyThread(final String name, final FailureCallback failureCallback, final long seed, final int workerId, final String property, IWorkerSession.IRemote workerSession) {
        super(name, failureCallback);
        this.random = new Random(seed);
        this.property = property;
        this.workerId = workerId;
        this.workerSession = workerSession;
        increment = new IncrementProperty(workerId, property, workerSession);
    }

    @Override
    public void run() {
        long expectedValue = getActualValue();
        try {
            while (!isStop()) {
                // Time to check
                if (getOperationsPerformed() % 10 == 0 || true) {
                    long actual = getActualValue();
                    if (expectedValue != actual) {
                        fireFailure("WORKER" + workerId + "." + property + ": expected " + expectedValue + ", actual: " + actual + " after increase " + getOperationsPerformed());
                        break;
                    }
                }
                // Increment
                increment.run();
                expectedValue++;
                // Sleep
                Thread.sleep((int) (random.nextDouble() * 500.0));
                increaseOperationsPerformed();
            }
        } catch (InterruptedException ex) {
            LOG.error("Interrupted");
        }
    }

    private long getActualValue() {
        return Long.parseLong(workerSession.getCurrentWorkerConfig(workerId).getProperty(property, "0"));
    }
    
}
