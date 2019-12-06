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

import java.util.Collections;
import java.util.List;
import javax.persistence.EntityManager;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.server.IProcessable;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.CryptoTokenHelper;
import org.signserver.server.cryptotokens.ICryptoTokenV4;

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
                           final Request signRequest,
                           final RequestContext requestContext) {
        return purpose == ICryptoTokenV4.PURPOSE_NEXTKEY ? nextKeyAlias : defaultAlias;
    }
    
    @Override
    public List<String> getFatalErrors() {
        return Collections.emptyList();
    }
}
