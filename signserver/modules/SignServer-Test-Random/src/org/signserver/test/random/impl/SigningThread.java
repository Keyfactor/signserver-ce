/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.test.random.impl;

import java.util.Random;
import org.apache.log4j.Logger;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.test.random.*;

/**
 * Repeatable performs a signing.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SigningThread extends WorkerThread {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(IncrementPropertyThread.class);
    private final WorkerSpec worker;
    private final IWorkerSession.IRemote workerSession;
    private final Random random;
    private final Sign sign;
    private final Pauser pauser;

    public SigningThread(final String name, final FailureCallback failureCallback, final Pauser pauser, final long seed, final WorkerSpec worker, final IWorkerSession.IRemote workerSession) {
        super(name, failureCallback);
        this.pauser = pauser;
        this.random = new Random(seed);
        this.worker = worker;
        this.workerSession = workerSession;
        sign = new Sign(worker, workerSession, random);
    }

    @Override
    public void run() {
        try {
            while (!isStop()) {
                if (pauser != null) {
                    pauser.pause();
                }
                try {
                    sign.run();
                } catch (FailedException ex) {
                    fireFailure("WORKER" + worker + " XML signing failed after " + getOperationsPerformed() + " signings: " + ex.getMessage());
                    break;
                }
                // Sleep
                Thread.sleep((int) (random.nextDouble() * 500.0));
                increaseOperationsPerformed();
            }
        } catch (InterruptedException ex) {
            LOG.error("Interrupted: " + ex.getMessage());
        }
    }
    
}
