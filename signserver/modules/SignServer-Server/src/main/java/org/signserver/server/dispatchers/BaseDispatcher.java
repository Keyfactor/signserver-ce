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

import java.util.LinkedList;
import java.util.List;
import org.apache.log4j.Logger;
import org.signserver.common.DispatcherStatus;
import org.signserver.common.WorkerStatus;
import org.signserver.server.BaseProcessable;
import org.signserver.server.signers.BaseSigner;

/**
 * Base class that all dispatchers can extend to cover basic in common
 * functionality.
 *
 * @version $Id$
 */
public abstract class BaseDispatcher extends BaseProcessable {
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(BaseSigner.class);
    
    /**
     * @return WorkerStatus
     * @see org.signserver.server.IProcessable#getStatus()
     */
    @Override
    public WorkerStatus getStatus(final List<String> additionalFatalErrors) {
        final List<String> fatalErrors = new LinkedList<String>(additionalFatalErrors);
        fatalErrors.addAll(getFatalErrors());
        return new DispatcherStatus(workerId, fatalErrors, config);
    }
}
