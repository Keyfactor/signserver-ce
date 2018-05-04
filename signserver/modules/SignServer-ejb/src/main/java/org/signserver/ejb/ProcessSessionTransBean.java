/** ***********************************************************************
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
 ************************************************************************ */
package org.signserver.ejb;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.server.log.AdminInfo;

/**
 * Session Bean handling the worker process requests when transaction is needed.
 *
 * @author Vinay Singh
 * @version $Id$
 */
@Stateless
public class ProcessSessionTransBean implements ProcessSessionTransLocal {

    /**
     * Log4j instance for this class.
     */
    private static final Logger LOG = Logger.getLogger(ProcessSessionTransBean.class);

    /**
     *
     * @param info
     * @param wi
     * @param request
     * @param requestContext
     * @param processImpl
     * @return
     * @throws IllegalRequestException
     * @throws CryptoTokenOfflineException
     * @throws SignServerException
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public Response processWithTransaction(final AdminInfo info,
            final WorkerIdentifier wi,
            final Request request,
            final RequestContext requestContext, WorkerProcessImpl processImpl)
            throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        if (LOG.isDebugEnabled()) {
            LOG.debug(">process in transaction: " + wi);
        }

        return processImpl.process(info, wi, request, requestContext);
    }

}
