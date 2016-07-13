/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.common.data;

import java.util.Map;

/**
 *
 * @author user
 */
public class TBNSODRequest extends TBNRequest {

    private final int requestID;
    private final Map<Integer, byte[]> dataGroupHashes;
    private final String ldsVersion;
    private final String unicodeVersion;
    private final WritableData responseData;
    
    public TBNSODRequest(int requestID, Map<Integer, byte[]> dataGroupHashes, String ldsVersion, String unicodeVersion, WritableData responseData) {
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
