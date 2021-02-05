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
 * Callback to invoke after a test failed in some thread.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public interface FailureCallback {
    /**
     * Called from different threads when a failure has happened.
     * @param thread The source thread of the failure
     * @param message A descriptive message of the failure
     */
    void failed(OperationsThread thread, String message);
}
