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

import java.util.Collections;
import java.util.List;
import javax.persistence.EntityManager;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;

/**
 * Simple IAuthorizer accepting all requests.
 * 
 * @author Philip Vendil 24 nov 2007
 * @version $Id$
 */
public class NoAuthorizer implements IAuthorizer {

    /**
     * @throws org.signserver.common.SignServerException
     * @see org.signserver.server.IAuthorizer#init(int, org.signserver.common.WorkerConfig, javax.persistence.EntityManager)
     */
    @Override
    public void init(int workerId, WorkerConfig config, EntityManager em)
            throws SignServerException {
    }

    /**
     * Check if a request is authorized.
     * 
     * @throws SignServerException
     * @throws IllegalRequestException If not authorized
     * @see org.signserver.server.IAuthorizer#isAuthorized(ProcessRequest, RequestContext)
     */
    @Override
    public void isAuthorized(Request request, RequestContext requestContext)
            throws SignServerException, IllegalRequestException {
    }

    @Override
    public List<String> getFatalErrors() {
        return Collections.emptyList();
    }
}
