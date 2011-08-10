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
package org.signserver.server.dispatchers;

import org.signserver.common.DispatcherStatus;
import org.signserver.common.WorkerStatus;
import org.signserver.server.BaseProcessable;

/**
 * Base class that all dispatchers can extend to cover basic in common
 * functionality.
 *
 * @version $Id$
 */
public abstract class BaseDispatcher extends BaseProcessable {

    /**
     * @return WorkerStatus
     * @see org.signserver.server.signers.IProcessable#getStatus()
     */
    public WorkerStatus getStatus() {
        return new DispatcherStatus(workerId, config);
    }
}
