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

import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestAndResponseManager;

/**
 * FetchKeyRequest is a process request sent to GroupKeyService in order to fetch a 
 * group key given a documentId.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class FetchKeyRequest extends ProcessRequest {

    private static final long serialVersionUID = 1L;
    // Not really used in this case.	
    private String documentId;
    private boolean genKeyIfNotExist = false;
    private int keyPart = GroupKeyServiceConstants.KEYPART_SYMMETRIC;

    /**
     * Default constructor used during serialization
     */
    public FetchKeyRequest() {
    }

    /**
     * Default constructor used to fetch a key using the default key type.
     * 
     * @param documentId unique identifier of a document
     * @param keyPart one of GroupKeyServiceConstants.KEYPART constants indicating part of key to fetch.
     * @param genKeyIfNotExist if key doesn't exists should a unassigned key be used, otherwise
     * will a IllegalRequestException be thrown.
     */
    public FetchKeyRequest(String documentId, int keyPart, boolean genKeyIfNotExist) {
        super();
        this.documentId = documentId;
        this.keyPart = keyPart;
        this.genKeyIfNotExist = genKeyIfNotExist;
    }

    /**
     * 
     * @return unique identifier of a document
     */
    public String getDocumentId() {
        return documentId;
    }

    /**
     * @return genKeyIfNotExist if key doesn't exists should a unassigned key be used, otherwise
     * will a IllegalRequestException be thrown.
     */
    public boolean isGenKeyIfNotExist() {
        return genKeyIfNotExist;
    }

    /**
     * @return one of GroupKeyServiceConstants.KEYPART_ constants indicating part of key to fetch.
     */
    public int getKeyPart() {
        return keyPart;
    }

    public void parse(DataInput in) throws IOException {
        in.readInt();
        int stringLen = in.readInt();
        byte[] stringData = new byte[stringLen];
        in.readFully(stringData);
        this.documentId = new String(stringData, "UTF-8");

        this.genKeyIfNotExist = in.readBoolean();
        this.keyPart = in.readInt();
    }

    public void serialize(DataOutput out) throws IOException {
        out.writeInt(RequestAndResponseManager.REQUESTTYPE_GKS_FETCHKEY);
        byte[] stringData = documentId.getBytes("UTF-8");
        out.writeInt(stringData.length);
        out.write(stringData);
        out.writeBoolean(genKeyIfNotExist);
        out.writeInt(keyPart);
    }
}
