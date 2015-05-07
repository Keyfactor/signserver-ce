/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.client.cli.defaultimpl;

import java.io.IOException;
import java.net.URL;

/**
 *
 * @author user
 */
public class HTTPException extends IOException {

    private final URL url;
    private final int responseCode;
    private final String responseMessage;
    private final byte[] responseBody;
    
    
    public HTTPException(URL url, int responseCode, String responseMessage, byte[] responseBody) {
        super("Server returned HTTP response code: " + responseCode + " for URL: " + url + ": " + responseMessage);
        this.url = url;
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
        this.responseBody = responseBody;
    }

    public URL getUrl() {
        return url;
    }

    public int getResponseCode() {
        return responseCode;
    }

    public String getResponseMessage() {
        return responseMessage;
    }

    public byte[] getResponseBody() {
        return responseBody;
    }
    
}
