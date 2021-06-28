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
import java.util.Map;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.server.IProcessable;
import org.signserver.server.WorkerContext;
import org.signserver.server.cryptotokens.CryptoTokenHelper;

/**
 * Alias selector using the ALIAS provided in the metadata of the request.
 * 
 * If no ALIAS is provided instead the default key is used.
 *
 * @author Antoine Louiset
 * @author Markus Kilås
 * @version $Id$
 */
public class RequestMetadataAliasSelector implements AliasSelector {

    private static final Logger LOG = Logger.getLogger(RequestMetadataAliasSelector.class);

    public static final String ALIAS = "ALIAS";

    private String defaultKey;

    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext,
            final EntityManager workerEM) {
        defaultKey = config.getProperty(CryptoTokenHelper.PROPERTY_DEFAULTKEY);
    }

    @Override
    public String getAlias(final int purpose, final IProcessable processble,
            final Request signRequest, final RequestContext requestContext) {
        if (requestContext != null) {
            final Object o = requestContext.get(RequestContext.REQUEST_METADATA);
            if (o instanceof Map) {
                final Map<String, String> metadata = (Map<String, String>) o;
                final String alias = metadata.get(ALIAS);
                if (alias == null) {
                    LOG.debug("No alias in request metadata");
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Using alias from request metadata: " + alias);
                    }
                    return alias;
                }
            }
        }
        return defaultKey;
    }

    @Override
    public List<String> getFatalErrors() {
        return Collections.emptyList();
    }
}
