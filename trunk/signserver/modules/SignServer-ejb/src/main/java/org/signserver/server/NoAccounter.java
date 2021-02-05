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

import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.common.RequestContext;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;

/**
 * Default account that grants all requests without charging anybody.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class NoAccounter implements IAccounter {

    private static final Logger LOG = Logger.getLogger(NoAccounter.class);

    @Override
    public void init(final Properties props) {
        LOG.debug("init");
    }

    @Override
    public boolean purchase(final IClientCredential credential,
            final Request request, final Response response,
            final RequestContext context) throws AccounterException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("purchase called for "
                + (String) context.get(RequestContext.TRANSACTION_ID));
        }

        // This IAccounter always grants without charging anybody
        return true;
    }
    
}
