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

/**
 * Callback to invoke after a test failed in some thread.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public interface FailureCallback {
    /**
     * Called from different threads when a failure has happened.
     * @param thread The source thread of the failure
     * @param message A descriptive message of the failure
     */
    void failed(WorkerThread thread, String message);
}
