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
package org.signserver.groupkeyservice.common;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestAndResponseManager;

/**
 * FetchKeyResponse is given by a GroupKeyService processing a FetchKeyRequest if
 * all the processing was successful.
 * 
 * @author phive
 * @author Philip Vendil
 * @version $Id$
 */
public class FetchKeyResponse extends ProcessResponse {

    private static final long serialVersionUID = 1L;
    private String documentId;
    private byte[] groupKey;

    /**
     * Default constructor used during serialization
     */
    public FetchKeyResponse() {
    }

    /**
     * Main constructor for the FetchKeyResponse
     * @param documentId the unique documentId that is related to the group key
     * @param groupKey the actual key, decrypted and object serialized.
     */
    public FetchKeyResponse(String documentId, byte[] groupKey) {
        this.documentId = documentId;
        this.groupKey = groupKey;
    }

    /**
     * @return documentId the unique documentId that is related to the group key
     */
    public String getDocumentId() {
        return documentId;
    }

    /**
     * @return the actual key, decrypted.
     */
    public byte[] getGroupKey() {
        return groupKey;
    }

    public void parse(DataInput in) throws IOException {
        in.readInt();
        int stringLen = in.readInt();
        byte[] stringData = new byte[stringLen];
        in.readFully(stringData);
        this.documentId = new String(stringData, "UTF-8");
        int keySize = in.readInt();
        groupKey = new byte[keySize];
        in.readFully(groupKey);
    }

    public void serialize(DataOutput out) throws IOException {
        out.writeInt(RequestAndResponseManager.RESPONSETYPE_GKS_FETCHKEY);
        byte[] stringData = documentId.getBytes("UTF-8");
        out.writeInt(stringData.length);
        out.write(stringData);
        out.writeInt(groupKey.length);
        out.write(groupKey);
    }
}
