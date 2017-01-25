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
package org.signserver.common.data;

/**
 * Data holder for a generic process request.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SignatureRequest extends Request {

    private final int requestID;
    private final ReadableData requestData;
    private final WritableData responseData;
    
    public SignatureRequest(int requestID, ReadableData requestData, WritableData responseData) {
        this.requestID = requestID;
        this.requestData = requestData;
        this.responseData = responseData;
    }

    public int getRequestID() {
        return requestID;
    }

    public ReadableData getRequestData() {
        return requestData;
    }

    public WritableData getResponseData() {
        return responseData;
    }

}
