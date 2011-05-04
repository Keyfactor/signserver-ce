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
import java.io.EOFException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.apache.log4j.Logger;

/**
 * Request used for signing data groups hashes and requesting a signed SO(D)
 * from the MRTD SOD Signer.
 *
 * Used for ePassports.
 * This is not located in the mrtdsod module package because it has to be
 * available at startup to map urls.
 *
 * @author Markus Kilas
 * @version $Id$
 */
public class SODSignRequest extends ProcessRequest implements ISignRequest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SODSignRequest.class);

    private static final long serialVersionUID = 1L;
    private int requestID; 
    private Map<Integer, byte[]> dataGroupHashes;
    private String ldsVersion;
    private String unicodeVersion;

    /**
     * Default constructor used during serialization.
     */
    public SODSignRequest() {
    }

    /**
     * Main constructor using default SHA256 and SHA256WithRSA as digest and
     * signature algorithms.
     *
     * @param requestID a unique id of the request
     * @param dataGroupHashes the dataData hashes to sign
     */
    public SODSignRequest(int requestID, Map<Integer, byte[]> dataGroupHashes) {
        this(requestID, dataGroupHashes, null, null);
    }

    /**
     * Constructs an instance of SODSignRequest using default algorithms and
     * by specifying both LDS version and Unicode version.
     *
     * @param requestID a unique id of the request
     * @param dataGroupHashes the dataData hashes to sign
     * @param ldsVersion version of the LDS
     * @param unicodeVersion version of Unicode
     */
    public SODSignRequest(final int requestID,
            final Map<Integer, byte[]> dataGroupHashes,
            final String ldsVersion, final String unicodeVersion) {
        super();
        this.requestID = requestID;
        this.dataGroupHashes = dataGroupHashes;
        this.ldsVersion = ldsVersion;
        this.unicodeVersion = unicodeVersion;
    }

    /**
     * @return The request ID
     */
    public int getRequestID() {
        return requestID;
    }

    /**
     * @return the signed data as an ArrayList of document objects to sign
     */
    public Object getRequestData() {
        return getDataGroupHashes();
    }

    /**
     * @return the map of datagroup hashes
     */
    public Map<Integer, byte[]> getDataGroupHashes() {
        return dataGroupHashes;
    }

    /**
     * @return The requested LDS version or null
     */
    public String getLdsVersion() {
        return ldsVersion;
    }

    /**
     * @return The requested unicode version or null
     */
    public String getUnicodeVersion() {
        return unicodeVersion;
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
        try {
            ldsVersion = in.readUTF();
            if (ldsVersion.isEmpty()) {
                ldsVersion = null;
            }
            try {
            	unicodeVersion = in.readUTF();
            	if (unicodeVersion.isEmpty()) {
            		unicodeVersion = null;
            	}
            } catch (EOFException ignored) {
                LOG.debug("No unicode version in request");
            }
        } catch (EOFException ignored) {
            LOG.debug("No LDS version in request");
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
        out.writeUTF(ldsVersion == null ? "" : ldsVersion);
        out.writeUTF(unicodeVersion == null ? "" : unicodeVersion);
    }
}
