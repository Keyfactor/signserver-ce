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
package org.signserver.module.sample.components;

import java.util.Properties;
import org.apache.log4j.Logger;
import org.signserver.common.RequestContext;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.server.AccounterException;
import org.signserver.server.IAccounter;
import org.signserver.server.IClientCredential;

/**
 * Skeleton accounter...
 * <p>
 *    The accounter has the following worker properties:
 * </p>
 * <ul>
 *    <li>
 *        <b>PROPERTY...</b> = Description... (Required/Optional, default: ...)
 *    </li>
 * </ul>
 *
 * @author ...
 * @version $Id$
 */
public class SkeletonAccounter implements IAccounter {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(SkeletonAccounter.class);

    // Worker properties
    //...

    // Log fields
    //...

    // Default values
    //...

    // Configuration values
    //...

    @Override
    public void init(final Properties props) {
        // Read properties
        //...
    }

    @Override
    public boolean purchase(final IClientCredential credential,
            final Request request, final Response response,
            final RequestContext context) throws AccounterException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("purchase called for "
                + (String) context.get(RequestContext.TRANSACTION_ID));
        }
        
        // Purchase logic, possibly using context.getEntityManager()
        //...

        // Purchase not granted
        return false;
    }

}
