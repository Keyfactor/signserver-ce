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

import java.util.Map;

/**
 * Data holder for a MRTD SOD signing request.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SODRequest extends Request {

    private final int requestID;
    private final Map<Integer, byte[]> dataGroupHashes;
    private final String ldsVersion;
    private final String unicodeVersion;
    private final WritableData responseData;
    
    public SODRequest(int requestID, Map<Integer, byte[]> dataGroupHashes, String ldsVersion, String unicodeVersion, WritableData responseData) {
        this.requestID = requestID;
        this.dataGroupHashes = dataGroupHashes;
        this.ldsVersion = ldsVersion;
        this.unicodeVersion = unicodeVersion;
        this.responseData = responseData;
    }

    public int getRequestID() {
        return requestID;
    }

    public Map<Integer, byte[]> getDataGroupHashes() {
        return dataGroupHashes;
    }

    public String getLdsVersion() {
        return ldsVersion;
    }

    public String getUnicodeVersion() {
        return unicodeVersion;
    }

    public WritableData getResponseData() {
        return responseData;
    }
    
}
