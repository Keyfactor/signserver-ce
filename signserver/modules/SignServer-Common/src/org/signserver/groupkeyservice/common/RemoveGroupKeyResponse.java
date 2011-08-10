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
 * Class containing info about the remove group keys
 * 
 * The info is:
 *   If the operation was successful
 *   Number of keys actually removed.
 *
 * @author Philip Vendil 13 nov 2007
 * @version $Id$
 */
public class RemoveGroupKeyResponse extends ProcessResponse {

    private static final long serialVersionUID = 1L;
    private boolean operationSuccessful = false;
    private long numOfKeysRemoved = 0;

    /**
     * Default constructor used during serialization
     */
    public RemoveGroupKeyResponse() {
    }

    /**
     * 
     * @param operationSuccessful true if the operation was successful
     * @param numOfKeysRemoved the number of keys actually removed.
     */
    public RemoveGroupKeyResponse(boolean operationSuccessful, long numOfKeysRemoved) {
        super();
        this.operationSuccessful = operationSuccessful;
        this.numOfKeysRemoved = numOfKeysRemoved;
    }

    /**
     * 
     * @return true if the operation was successful
     */
    public boolean wasOperationSuccessful() {
        return operationSuccessful;
    }

    /**
     * 
     * @return the number of keys actually removed.
     */
    public long getNumOfKeysRemoved() {
        return numOfKeysRemoved;
    }

    public void parse(DataInput in) throws IOException {
        in.readInt();
        numOfKeysRemoved = in.readLong();
        operationSuccessful = in.readBoolean();
    }

    public void serialize(DataOutput out) throws IOException {
        out.writeInt(RequestAndResponseManager.RESPONSETYPE_GKS_REMOVEKEY);
        out.writeLong(numOfKeysRemoved);
        out.writeBoolean(operationSuccessful);
    }
}
