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
package org.signserver.server;

import javax.persistence.EntityManager;
import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.entities.IKeyUsageCounterDataService;

/**
 * SignServer specific context, contains the Entity Manager
 * so the workers can access it.
 * 
 * @author Philip Vendil 3 aug 2008
 * @version $Id$
 */
public class SignServerContext extends WorkerContext {

    private final EntityManager em;
    private final IKeyUsageCounterDataService keyUsageCounterDataService;
    private CryptoTokenSupplier cryptoTokenSupplier;

    public SignServerContext() {
        this(null, null);
    }

    public SignServerContext(EntityManager em, IKeyUsageCounterDataService keyUsageCounterDataService) {
        this.em = em;
        this.keyUsageCounterDataService = keyUsageCounterDataService;
    }

    public SignServerContext newInstance() {
        return new SignServerContext(em, keyUsageCounterDataService);
    }

    /**
     * 
     * @return Entity Manager.
     * @deprecated This EntityManager was created when the SignServerContext was 
     * created and is not safe to use from an other transaction. Instead 
     * use the entity manager available in the RequestContext.
     */
    @Deprecated
    public EntityManager getEntityManager() {
        return em;
    }

    public IKeyUsageCounterDataService getKeyUsageCounterDataService() {
        return keyUsageCounterDataService;
    }
    
    /**
     * @return True if a database was configured for SignServer
     */
    public boolean isDatabaseConfigured() {
        return em != null;
    }

    public void setCryptoTokenSupplier(CryptoTokenSupplier cryptoTokenSupplier) {
        this.cryptoTokenSupplier = cryptoTokenSupplier;
    }

    public ICryptoToken getCryptoToken() throws SignServerException {
        ICryptoToken result = null;
        if (cryptoTokenSupplier != null) {
            result = cryptoTokenSupplier.getCurrentCryptoToken();
        }
        return result;
    }

}
