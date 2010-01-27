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
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;

/**
 * Authorizer that examines the RequestContext and only accepts requests if
 * the value Boolean.TRUE is set for RequestContextDISPATCHER_AUTHORIZED_CLIENT.
 *
 * This authorizer can be set for all worker if a dispatcher such as the
 * TSADispatcherServlet is resposible for looking up the authorization and it
 * should not be possible to call the workers directly using for instance the
 * GenericProcessServlet.
 * 
 * @author markus
 * @version $Id$
 * @see RequestContext#DISPATCHER_AUTHORIZED_CLIENT
 */
public class DispatchedAuthorizer implements IAuthorizer {

    private int workerId;


    public void init(int workerId, WorkerConfig config, EntityManager em) throws SignServerException {
        this.workerId = workerId;
    }

    public void isAuthorized(final ProcessRequest request,
            final RequestContext requestContext)
                throws IllegalRequestException, SignServerException {

        if (!authorizedToRequest(requestContext)) {
            throw new IllegalRequestException(
                    "Error, client is not authorized to worker with id "
                    + workerId);
        }
    }

    private boolean authorizedToRequest(final RequestContext context) {
        final boolean result;
        final Object value = context.get(
                RequestContext.DISPATCHER_AUTHORIZED_CLIENT);
        
        if (value instanceof Boolean) {
            result = (Boolean) value;
        } else {
            result = false;
        }

        return result;
    }

}
