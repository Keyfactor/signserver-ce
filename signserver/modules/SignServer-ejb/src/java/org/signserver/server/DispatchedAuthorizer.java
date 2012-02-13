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
import org.apache.log4j.Logger;
import org.signserver.common.*;

/**
 * Authorizer that examines the RequestContext and only accepts requests if
 * the value Boolean.TRUE is set for RequestContext.DISPATCHER_AUTHORIZED_CLIENT.
 *
 * This authorizer can be set for all worker if a dispatcher such as the
 * TSADispatcherServlet is resposible for looking up the authorization and it
 * should not be possible to call the workers directly using for instance the
 * GenericProcessServlet.
 * 
 * AUTHORIZEALLDISPATCHERS = True, if any Dispatcher should be authorized. (Default: true, currently only true is supported)
 * 
 * @author Markus Kilås
 * @version $Id$
 * @see RequestContext#DISPATCHER_AUTHORIZED_CLIENT
 */
public class DispatchedAuthorizer implements IAuthorizer {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(DispatchedAuthorizer.class);
    
    private static final String AUTHORIZEALLDISPATCHERS = "AUTHORIZEALLDISPATCHERS";
    
    private int workerId;

    private boolean authorizeAllDispatchers;

    

    @Override
    public void init(int workerId, WorkerConfig config, EntityManager em) throws SignServerException {
        this.workerId = workerId;
        
        String value = config.getProperty(AUTHORIZEALLDISPATCHERS);
        if (value == null) {
            LOG.error("DispatchedAuthorizer[" + workerId + "]: Missing property " + AUTHORIZEALLDISPATCHERS);
        } else {
            authorizeAllDispatchers = Boolean.parseBoolean(value);
        }
    }

    @Override
    public void isAuthorized(final ProcessRequest request,
            final RequestContext requestContext)
                throws IllegalRequestException, SignServerException {

        if (!authorizeAllDispatchers || !authorizedToRequest(requestContext)) {
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
