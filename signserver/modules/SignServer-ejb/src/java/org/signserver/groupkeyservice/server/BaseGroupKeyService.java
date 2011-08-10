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
     * @see org.signserver.server.IWorker#init(int, org.signserver.common.WorkerConfig,EntityManager)
     */
    public void init(int workerId, WorkerConfig config, EntityManager em, IExtendedCryptoToken ect) {
        this.workerId = workerId;
        this.config = config;
        this.em = em;
        this.ect = ect;
    }
}
