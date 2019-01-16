/*************************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or*
 *  modify it under the terms of the GNU Lesser General Public    *
 *  License as published by the Free Software Foundation; either  *
 *  version 2.1 of the License, or any later version.               *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
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
