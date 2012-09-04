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
package org.signserver.groupkeyservice.server;

import java.util.Collections;
import java.util.List;
import javax.persistence.EntityManager;
import org.signserver.common.WorkerConfig;
import org.signserver.server.cryptotokens.IExtendedCryptoToken;

/**
 * Base class of a BaseGroup Key Service taking care of basic functionality
 * such as initializing and creating the extended crypto token.
 * 
 * @author Philip Vendil 23 nov 2007
 * @version $Id$
 */
public abstract class BaseGroupKeyService implements IGroupKeyService {

    protected int workerId;
    protected WorkerConfig config;
    protected EntityManager em;
    protected IExtendedCryptoToken ect;

    /**
     * @see org.signserver.server.IWorker#init(int, org.signserver.common.WorkerConfig, org.signserver.server.WorkerContext, javax.persistence.EntityManager)
     */
    @Override
    public void init(int workerId, WorkerConfig config, EntityManager em, IExtendedCryptoToken ect) {
        this.workerId = workerId;
        this.config = config;
        this.em = em;
        this.ect = ect;
    }
    
    /**
     * Method that can be overridden by IWorker implementations to give an 
     * up to date list of errors that would prevent a call to the process 
     * method to succeed.
     * If the returned list is non empty the worker will be reported as offline 
     * in status listings and by the health check (unless the worker is disabled).
     * @return A list of (short) messages describing each error or an empty list
     * in case there are no errors
     * @since SignServer 3.2.3
     */
    protected List<String> getFatalErrors() {
        return Collections.emptyList();
    }
}
