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
import org.signserver.groupkeyservice.common.FetchKeyRequest;
import org.signserver.groupkeyservice.common.IRemoveGroupKeyRequest;
import org.signserver.groupkeyservice.common.PregenerateKeysRequest;
import org.signserver.groupkeyservice.common.SwitchEncKeyRequest;

/**
 * Abstract base class that all group service authorizer should inherit.
 * 
 * It makes sure that non-fetchKey requests should only be called from 
 * the CLI. I have one abstract method used to authorize FetchKeyRequests.
 * 
 * 
 * @author Philip Vendil
 *  $Id$
 */
public abstract class BaseGroupKeyServiceAuthorizer implements IAuthorizer {

    protected int workerId;
    protected WorkerConfig config;
    protected EntityManager em;

    public void init(int workerId, WorkerConfig config, EntityManager em)
            throws SignServerException {
        this.workerId = workerId;
        this.config = config;
        this.em = em;
    }

    /**
     * Method that checks that all non-fetchkey requests is called from CLI.
     */
    public void isAuthorized(ProcessRequest request,
            RequestContext requestContext) throws IllegalRequestException,
            SignServerException {
        if (request instanceof FetchKeyRequest) {
            isFetchKeyRequestAuthorized(request, requestContext);
        } else {
            if (request instanceof IRemoveGroupKeyRequest
                    || request instanceof SwitchEncKeyRequest
                    || request instanceof PregenerateKeysRequest) {
                if (!requestContext.isCalledFromCLI()) {
                    throw new IllegalRequestException("Request Type can only be called from CLI interface :" + request.getClass().getName());
                }
            } else {
                throw new IllegalRequestException("Unsupported Request Type : " + request.getClass().getName());
            }
        }
    }

    public abstract void isFetchKeyRequestAuthorized(ProcessRequest request,
            RequestContext requestContext) throws IllegalRequestException,
            SignServerException;
}
