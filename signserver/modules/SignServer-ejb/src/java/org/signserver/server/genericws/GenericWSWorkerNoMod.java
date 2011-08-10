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
package org.signserver.server.genericws;

import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatus;
import org.signserver.server.BaseProcessable;
import org.signserver.server.WorkerContext;

/**
 * Class managing a custom JAX-WS web service. It'made so it is possible
 * to develop your own JX-WS web service and have it as a worker. 
 * 
 * This class is different from GenericWSWorker in that it works with and
 * requires includedmodulesinbuild=true.
 *
 * @version $Id$
 */
public class GenericWSWorkerNoMod extends BaseProcessable {

    private GenericWSWorkerImpl delegate;

    public GenericWSWorkerNoMod() {
        this.delegate = new GenericWSWorkerImpl(false);
    }

    /**
     * Initialization method creating the validation service
     * @see org.signserver.server.BaseWorker#init(int, org.signserver.common.WorkerConfig, javax.persistence.EntityManager)
     */
    @Override
    public void init(int workerId, WorkerConfig config, WorkerContext workerContext,EntityManager workerEntityManager) {
            super.init(workerId, config, workerContext,workerEntityManager);
            delegate.init(workerId, config, workerContext, workerEM);
    }

    /**
     * Main method of the container calling the appropriate method
     * of the ValidationService depending on the type of request.
     *
     * @see org.signserver.server.signers.IProcessable#processData(
     * org.signserver.common.ProcessRequest, java.security.cert.X509Certificate)
     */
    public ProcessResponse processData(ProcessRequest processRequest,
    		RequestContext requestContext) throws IllegalRequestException,
    		CryptoTokenOfflineException, SignServerException {
        return delegate.processData(processRequest, requestContext);
    }

    @Override
    public WorkerStatus getStatus() {
        return delegate.getStatus();
    }
}
