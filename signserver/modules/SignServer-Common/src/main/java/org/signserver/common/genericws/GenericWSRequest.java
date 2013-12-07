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
package org.signserver.common.genericws;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.signserver.common.GenericSignRequest;

/**
 *  A VO used for generic WebServices, in the case a MAR module
 *  wan't to provide a jax-ws interface instead of a regulare
 *  process call.
 *  
 *  Used for transporting the request and response objects from
 *  the web container to the GenericWSWorker.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class GenericWSRequest extends GenericSignRequest {

    public static final int REQUESTTYPE_GET = 1;
    public static final int REQUESTTYPE_POST = 2;
    public static final int REQUESTTYPE_PUT = 3;
    public static final int REQUESTTYPE_DEL = 4;
    public static final int REQUESTTYPE_CONTEXT_INIT = 5;
    public static final int REQUESTTYPE_CONTEXT_DESTROYED = 6;
    private static final long serialVersionUID = 1L;
    private HttpServletRequest httpServletRequest;
    private HttpServletResponse httpServletRespone;
    private ServletConfig servletConfig;
    private int requestType;
    private ServletContext servletContext;

    /**
     * Creates a GenericSignRequest, works as a simple VO.
     * 
     * @param requestID number identifying the request
     * @param requestType one of the REQUESTTYPE constants.
     * @param req the current HttpServletRequest
     * @param res the current HttpServletResponse
     * @param config the current ServletConfig
     * @param servletContext used for listener calls
     * @see org.signserver.common.ProcessRequest
     */
    public GenericWSRequest(int requestId, int requestType, HttpServletRequest req, HttpServletResponse res, ServletConfig config, ServletContext servletContext) {
        super(requestId, null);
        this.requestType = requestType;
        this.httpServletRequest = req;
        this.httpServletRespone = res;
        this.servletConfig = config;
        this.servletContext = servletContext;
    }

    /**
     * @return the httpServletRequest of the current HTTP request.
     */
    public HttpServletRequest getHttpServletRequest() {
        return httpServletRequest;
    }

    /**
     * @return the httpServletRespone
     */
    public HttpServletResponse getHttpServletResponse() {
        return httpServletRespone;
    }

    /**
     * @return the servletConfig
     */
    public ServletConfig getServletConfig() {
        return servletConfig;
    }

    /**
     * @return the requestType  on of REQUESTTYPE_ constants
     */
    public int getRequestType() {
        return requestType;
    }

    /**
     * @return the servletContext used for context listener calls.
     */
    public ServletContext getServletContext() {
        return servletContext;
    }
}
