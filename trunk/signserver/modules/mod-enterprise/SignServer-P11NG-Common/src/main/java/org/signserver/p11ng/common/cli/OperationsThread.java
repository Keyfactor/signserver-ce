/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.p11ng.common.cli;

/**
 * Abstract thread implementation handling failure callback and stop flag.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public abstract class OperationsThread  extends Thread {
    private final FailureCallback failureCallback;
    private volatile boolean stop;
    private int numOperations;
    
    public OperationsThread(final FailureCallback failureCallback) {
        this.failureCallback = failureCallback;
    }
    
    /**
     * Indicate that this thread has discovered a failure.
     * @param message A description of the problem
     */
    protected void fireFailure(final String message) {
        failureCallback.failed(this, message);
    }
    
    public void stopIt() {
        stop = true;
    }
    
    public boolean isStop() {
        return stop;
    }
    
    public int getNumberOfOperations() {
        return numOperations;
    }
    
    public void registerOperation() {
        numOperations++;
    }
}
