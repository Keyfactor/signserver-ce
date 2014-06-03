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
package org.signserver.ejb.interfaces;

import javax.ejb.Local;
import javax.ejb.Remote;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.server.log.AdminInfo;

/**
 * Interface for the internal worker session bean that should be used by
 * dispatchers.
 * Implements the process and getWorkerId methods as in the normal worker
 * session bean. However, this bean is not intended to be called directly by
 * the client through any of the interfaces but instead by dispatchers.
 *
 * @version $Id$
 * @see IWorkerSession
 * @see IInternalWorkerSession
 */
public interface IDispatcherWorkerSession {

    /**
     * @see IWorkerSession#process(int, org.signserver.common.ProcessRequest, org.signserver.common.RequestContext)
     */
    ProcessResponse process(int workerId, ProcessRequest request,
            RequestContext requestContext)
            throws IllegalRequestException, CryptoTokenOfflineException,
            SignServerException;

    /**
     * @see IWorkerSession#getWorkerId(java.lang.String)
     */
    int getWorkerId(String workerName);

    /** Remote view. */
    @Remote
    interface IRemote extends IDispatcherWorkerSession {}

    /** Local view. */
    @Local
    interface ILocal extends IDispatcherWorkerSession { 

        /**
         * @see IWorkerSession.ILocal#process(org.signserver.server.log.AdminInfo, int, org.signserver.common.ProcessRequest, org.signserver.common.RequestContext)
         */
        ProcessResponse process(final AdminInfo info, int workerId, ProcessRequest request,
                RequestContext requestContext)
                throws IllegalRequestException, CryptoTokenOfflineException,
                SignServerException;

    }
}
