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

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

/**
 * A Generic work request class implementing the minimal required functionality.
 * 
 * Could be used for XML signature validation requests.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class GenericValidationRequest extends ProcessRequest implements IValidationRequest {

    private static final long serialVersionUID = 1L;
    private int requestID;
    private byte[] requestData;

    /**
     * Default constructor used during serialization
     */
    public GenericValidationRequest() {
        super();
    }

    /**
     * Creates a GenericValidationRequest, works as a simple VO.
     * 
     * @param requestID
     * @param requestData
     * @see org.signserver.common.ProcessRequest
     */
    public GenericValidationRequest(int requestID, byte[] requestData) {
        this.requestID = requestID;
        this.requestData = requestData;
    }

    /**
     * Get the request ID.
     * 
     * @return The request ID
     * @see org.signserver.common.ProcessRequest
     */
    @Override
    public int getRequestID() {
        return requestID;
    }

    /**
     * Get the request data.
     * 
     * @return The request data
     * @see org.signserver.common.ProcessRequest
     */
    @Override
    public byte[] getRequestData() {
        return requestData;
    }

    @Override
    public void parse(DataInput in) throws IOException {
        in.readInt();
        this.requestID = in.readInt();
        int dataSize = in.readInt();
        this.requestData = new byte[dataSize];
        in.readFully(requestData);
    }

    @Override
    public void serialize(DataOutput out) throws IOException {
        out.writeInt(RequestAndResponseManager.REQUESTTYPE_GENERICVALIDATION);
        out.writeInt(requestID);
        out.writeInt(requestData.length);
        out.write(requestData);
    }
}
