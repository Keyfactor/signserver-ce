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
import java.util.ArrayList;

/**
 * Class used to send data to the signSession.signData method and contain information
 * specific to MRTD signing.
 *
 * @author Philip Vendil
 * @version $Id$
 */
public class MRTDSignRequest extends ProcessRequest implements ISignRequest {

    private static final long serialVersionUID = 1L;
    private int requestID = 0;
    private ArrayList<byte[]> signRequestData = null;
    private static final String signatureAlgorithm = "RSASSA-PSS";

    /**
     * Default constructor used during serialization
     */
    public MRTDSignRequest() {
    }

    /**
     * Main constuctor.
     * 
     * @param requestID a unique id of the request
     * @param signRequestData the data about to sign. Should be of type byte[]
     */
    public MRTDSignRequest(int requestID, ArrayList<byte[]> signRequestData) {
        this.requestID = requestID;
        this.signRequestData = signRequestData;
    }

    /**
     * 
     * @see org.signserver.common.ProcessRequest#getRequestID()
     */
    public int getRequestID() {
        return requestID;
    }

    /**
     * Returns the signed data as an ArrayList of document objects to sign.
     */
    public Object getRequestData() {
        return signRequestData;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void parse(DataInput in) throws IOException {
        in.readInt();
        this.requestID = in.readInt();
        int arraySize = in.readInt();
        this.signRequestData = new ArrayList<byte[]>();
        for (int i = 0; i < arraySize; i++) {
            int dataSize = in.readInt();
            byte[] data = new byte[dataSize];
            in.readFully(data);
            signRequestData.add(data);
        }

    }

    public void serialize(DataOutput out) throws IOException {
        out.writeInt(RequestAndResponseManager.REQUESTTYPE_MRTDSIGNREQUEST);
        out.writeInt(this.requestID);
        out.writeInt(this.signRequestData.size());
        for (byte[] data : signRequestData) {
            out.writeInt(data.length);
            out.write(data);
        }
    }
}
