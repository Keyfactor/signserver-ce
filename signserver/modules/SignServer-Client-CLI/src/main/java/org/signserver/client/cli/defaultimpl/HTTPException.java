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
package org.signserver.client.cli.defaultimpl;

import java.io.IOException;
import java.net.URL;

/**
 * Exception indicating an error at the HTTP level.
 * Contains more information about the failure.
 *
 * @author Markus Kilås
 * @version $Id$
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
