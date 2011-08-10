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
import java.security.cert.CertificateEncodingException;
import java.util.Collection;

import javax.xml.bind.annotation.XmlTransient;

import org.ejbca.util.Base64;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestAndResponseManager;

/**
 * WebService representation of a signature response, corresponding
 * the the existing GeneralSignatureRespose class.
 *
 * @author Philip Vendil 28 okt 2007
 * @version $Id: ProcessResponseWS.java 500 2009-04-22 12:10:07Z anatom $
 */
public class ProcessResponseWS {

    private int requestID;
    private String responseDataBase64;
    private Certificate workerCertificate;
    private Collection<Certificate> workerCertificateChain;

    /**
     * Default constructor
     */
    public ProcessResponseWS() {
    }

    /**
     * Constructor using non-WS objects.
     * @throws CertificateEncodingException 
     */
    public ProcessResponseWS(int requestID, byte[] responseData) throws CertificateEncodingException {
        this.requestID = requestID;
        setResponseData(responseData);
    }

    /**
     * 
     * @return the request id sent in the request to identify the response if more
     * than one request was called in one call.
     */
    public int getRequestID() {
        return requestID;
    }

    /**
     * @param requestID the request id sent in the request to identify the response if more
     * than one request was called in one call.
     */
    public void setRequestID(int requestID) {
        this.requestID = requestID;
    }

    /**
     * @return the processed data in base64 encoding.
     */
    public String getResponseDataBase64() {
        return responseDataBase64;
    }

    /**
     * @param responseDataBase64 the processed data in base64 encoding.
     */
    public void setResponseDataBase64(String responseDataBase64) {
        this.responseDataBase64 = responseDataBase64;
    }

    /**
     * 
     * @return the entire  signer certificate chain in WS format.
     */
    public Collection<Certificate> getWorkerCertificateChain() {
        return workerCertificateChain;
    }

    /**
     * 
     * @return the worker certificate  in WS format.
     */
    public Certificate getWorkerCertificate() {
        return workerCertificate;
    }

    /**
     * 
     * @param workerCertificate the worker certificate  in WS format.
     */
    public void setWorkerCertificate(Certificate workerCertificate) {
        this.workerCertificate = workerCertificate;
    }

    /**
     * 
     * @param workerCertificateChain the entire  worker certificate chain in WS format.
     */
    public void setWorkerCertificateChain(
            Collection<Certificate> workerCertificateChain) {
        this.workerCertificateChain = workerCertificateChain;
    }

    /**
     * Help method used to set the processed data from binary form. 
     * @param signedData the data to base64 encode
     */
    @XmlTransient
    public void setResponseData(byte[] processedData) {
        if (processedData != null) {
            this.responseDataBase64 = new String(Base64.encode(processedData));
        }
    }

    /**
     * Help method returning the processed data in bytearray form. 
     * @param processedData the actual data
     */
    public byte[] getResponseData() {
        if (responseDataBase64 == null) {
            return null;
        }
        return Base64.decode(responseDataBase64.getBytes());
    }

    /**
     * Help method used to extract the IProcessResponse from
     * the WS response
     * @throws IOException if parsing of data failed.
     */
    @XmlTransient
    public ProcessResponse getProcessResponse() throws IOException {
        return RequestAndResponseManager.parseProcessResponse(getResponseData());
    }
}
