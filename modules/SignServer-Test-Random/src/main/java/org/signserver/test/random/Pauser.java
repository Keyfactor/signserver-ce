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
package org.signserver.test.random;

import org.apache.log4j.Logger;

/**
 * Class giving the threads the ability to do synchronized pauses.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Pauser {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(Pauser.class);
    private boolean pause;

    /**
     * Pauses all threads.
     */
    public void startPause() {
        synchronized (this) {
            this.pause = true;
        }
    }

    /**
     * Un-pauses all threads.
     */
    public void stopPause() {
        synchronized (this) {
            this.pause = false;
            notifyAll();
        }
    }
    
    /**
     * Checks if it is time to pause and if it is pauses otherwise just returns.
     */
    public void pause() throws InterruptedException {
        synchronized (this) {
            while (pause) {
                LOG.info(Thread.currentThread() + ": pausing");
                wait();
            }
        }
    }
}
