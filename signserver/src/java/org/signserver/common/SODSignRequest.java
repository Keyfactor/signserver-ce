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
import java.util.HashMap;
import java.util.Map;

/** Request used for signing data groups hashes and requesting a signed SO(D) from the MRTD SOD Signer. Used for ePassports.
 * 
 * This is not located in the mrtdsod module package because it has to be available at startup to map urls.
 *
 * @author Markus Kilas
 * @version $Id$
 */
public class SODSignRequest extends ProcessRequest implements ISignRequest {

    private static final long serialVersionUID = 1L;
    private int requestID;
    /** The requested digestAlgorithm, for example SHA1, SHA256. Defaults to SHA256. */
    private String digestAlgorithm = "SHA256"; 
	/** The requested digestEncryptionAlgorithm, for example SHA1withRSA, SHA256withRSA, SHA256withECDSA. Defaults to SHA256withRSA. */
    private String digestEncryptionAlgorithm = "SHA256withRSA"; 
    private Map<Integer, byte[]> dataGroupHashes;

    /**
     * Default constructor used during serialization
     */
    public SODSignRequest() {
    }

    /**
     * Main constructor using default SHA256 and SHA256WithRSA as digest and signature algorithms.
     *
     * @param requestID a unique id of the request
     * @param dataGroups the dataData hashes to sign
     */
    public SODSignRequest(int requestID, Map<Integer, byte[]> dataGroupHashes) {
        this.requestID = requestID;
        this.dataGroupHashes = dataGroupHashes;
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
        return getDataGroupHashes();
    }

    public String getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public void setDigestAlgorithm(String digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	public String getDigestEncryptionAlgorithm() {
		return digestEncryptionAlgorithm;
	}

	public void setDigestEncryptionAlgorithm(String digestEncryptionAlgorithm) {
		this.digestEncryptionAlgorithm = digestEncryptionAlgorithm;
	}

    public Map<Integer, byte[]> getDataGroupHashes() {
        return dataGroupHashes;
    }

    public void parse(DataInput in) throws IOException {
        in.readInt();
        this.requestID = in.readInt();
        int mapSize = in.readInt();
        this.dataGroupHashes = new HashMap<Integer, byte[]>(mapSize);
        for (int i = 0; i < mapSize; i++) {
            int key = in.readInt();
            int valueSize = in.readInt();
            byte[] value = new byte[valueSize];
            in.readFully(value);
            dataGroupHashes.put(key, value);
        }
    }

    public void serialize(DataOutput out) throws IOException {
        out.writeInt(RequestAndResponseManager.REQUESTTYPE_SODSIGNREQUEST);
        out.writeInt(this.requestID);
        out.writeInt(this.dataGroupHashes.size());
        for(Map.Entry<Integer, byte[]> entry : dataGroupHashes.entrySet()) {
            out.writeInt(entry.getKey().intValue());
            out.writeInt(entry.getValue().length);
            out.write(entry.getValue());
        }
    }
}
