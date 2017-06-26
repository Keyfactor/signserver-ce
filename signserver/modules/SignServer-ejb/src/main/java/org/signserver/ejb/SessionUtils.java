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
package org.signserver.ejb;

import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.worker.impl.PreloadedWorkerConfig;
import org.signserver.ejb.worker.impl.WorkerManagerSingletonBean;
import org.signserver.ejb.worker.impl.WorkerWithComponents;

/**
 * Utility functions for session beans.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class SessionUtils {
    /**
     * Checks if a process request should be run inside a transaction.
     * 
     * @param session
     * @param wi
     * @return true if the request needs a transaction
     */
    public static boolean needsTransaction(final WorkerManagerSingletonBean session,
                                           final WorkerIdentifier wi) {
        try {
            final WorkerWithComponents worker = session.getWorkerWithComponents(wi);
            final PreloadedWorkerConfig pwc = worker.getPreloadedConfig();

            return !worker.getArchivers().isEmpty() ||
                   !pwc.isDisableKeyUsageCounter() || pwc.isKeyUsageLimitSpecified();
        } catch (NoSuchWorkerException e) {
            return false;
        }
    }
}
