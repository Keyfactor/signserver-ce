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
package org.signserver.common;

import javax.servlet.http.HttpServletRequest;

/**
 * Request objects created by the GenericProcessServlet and sent to the processable workers
 * process method. Extends the GenericSignRequest method with a referense the the httpServletRequest. 
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class GenericServletRequest extends GenericSignRequest {

    private static final long serialVersionUID = 1L;
    
    private HttpServletRequest httpServletRequest;

    /**
     * Default constructor used during serialization
     */
    public GenericServletRequest() {
        super();
    }

    /**
     * Creates a GenericSignRequest, works as a simple VO.
     * 
     * @param requestID
     * @param requestData
     * @param req the current HttpServletRequest
     * @see org.signserver.common.ProcessRequest
     */
    public GenericServletRequest(int requestID, byte[] requestData, HttpServletRequest req) {
        super(requestID, requestData);
        this.httpServletRequest = req;
    }

    /**
     * @return the httpServletRequest of the current HTTP request.
     */
    public HttpServletRequest getHttpServletRequest() {
        return httpServletRequest;
    }
}
