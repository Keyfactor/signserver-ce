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
package org.signserver.server.aliasselectors;

import javax.persistence.EntityManager;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.IProcessable;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 * Default alias selector giving the DEFAULTKEY alias configured for the
 * current worker.
 * This is the default alias selector used if no alias selector has been
 * configured for a worker.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class DefaultAliasSelector implements AliasSelector {
    
    private String defaultAlias;
    private String nextKeyAlias;

    @Override
    public void init(final int workerId, final WorkerConfig config,
                     final WorkerContext workerContext,
                     final EntityManager workerEM) {
        defaultAlias = config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY);
        nextKeyAlias = config.getProperty(CryptoTokenHelper.PROPERTY_NEXTCERTSIGNKEY);
    }

    @Override
    public String getAlias(final int purpose, final IProcessable processble,
                           final ProcessRequest signRequest,
                           final RequestContext requestContext) {
        return purpose == ICryptoToken.PURPOSE_NEXTKEY ? nextKeyAlias : defaultAlias;
    }
}
