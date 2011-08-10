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
package org.signserver.protocol.ws;

import java.io.IOException;

import javax.xml.bind.annotation.XmlTransient;

import org.ejbca.util.Base64;
import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestAndResponseManager;

/**
 * WebService representation of a signature request, corresponding
 * the the existing GeneralSignatureRequest class.
 * 
 * @author Philip Vendil 28 okt 2007
 * @version $Id: ProcessRequestWS.java 500 2009-04-22 12:10:07Z anatom $
 */
public class ProcessRequestWS {

    private String requestDataBase64;

    public ProcessRequestWS() {
    }

    public ProcessRequestWS(byte[] requestData) {
        super();
        setRequestData(requestData);
    }

    public ProcessRequestWS(ProcessRequest processRequest) throws IOException {
        super();
        setRequestData(RequestAndResponseManager.serializeProcessRequest(processRequest));
    }

    /**
     * 
     * @return Base64 encoded string containing the request data.
     */
    public String getRequestDataBase64() {
        return requestDataBase64;
    }

    /**
     * 
     * @param requestDataBase64 encoded string containing the request data.
     */
    public void setRequestDataBase64(String requestDataBase64) {
        this.requestDataBase64 = requestDataBase64;
    }

    /**
     * Help method used to set the request from binary form. 
     * @param requestData the data to base64 encode
     */
    @XmlTransient
    public void setRequestData(byte[] requestData) {
        if (requestData != null) {
            this.requestDataBase64 = new String(Base64.encode(requestData));
        }
    }

    /**
     * Help method returning the  request data in binary form. 
     * @param signedData the actual data
     */
    public byte[] getRequestData() {
        if (requestDataBase64 == null) {
            return null;
        }
        return Base64.decode(requestDataBase64.getBytes());
    }
}
