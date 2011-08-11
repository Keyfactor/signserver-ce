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
package org.signserver.module.wsra.ws;

import java.security.Principal;

import javax.persistence.EntityManager;
import javax.xml.ws.EndpointReference;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.genericws.BaseWS;
import org.w3c.dom.Element;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class WSRATestWSContext implements WebServiceContext {

    private int workerId;
    private EntityManager workerEM;
    private WorkerConfig config;
    private RequestContext requestContext;
    private ICryptoToken cryptoToken;

    public WSRATestWSContext(int workerId, EntityManager workerEM,
            WorkerConfig config, RequestContext requestContext,
            ICryptoToken cryptoToken) {
        super();
        this.workerId = workerId;
        this.workerEM = workerEM;
        this.config = config;
        this.requestContext = requestContext;
        this.cryptoToken = cryptoToken;
    }

    public EndpointReference getEndpointReference(Element... arg0) {
        return null;
    }

    public <T extends EndpointReference> T getEndpointReference(
            Class<T> arg0, Element... arg1) {
        return null;
    }

    public MessageContext getMessageContext() {
        WSRATestHTTPRequest req = new WSRATestHTTPRequest();
        req.setAttribute(BaseWS.WORKERID, workerId);
        req.setAttribute(BaseWS.WORKERENTITYMANAGER, workerEM);
        req.setAttribute(BaseWS.WORKERCONFIG, config);
        req.setAttribute(BaseWS.REQUESTCONTEXT, requestContext);
        req.setAttribute(BaseWS.CRYPTOTOKEN, cryptoToken);
        MessageContext msgCtx = new WSRATestMessageContext();
        msgCtx.put(MessageContext.SERVLET_REQUEST, req);

        return msgCtx;
    }

    public Principal getUserPrincipal() {
        return null;
    }

    public boolean isUserInRole(String arg0) {
        return false;
    }
}