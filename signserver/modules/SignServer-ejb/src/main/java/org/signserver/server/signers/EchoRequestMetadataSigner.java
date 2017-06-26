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
package org.signserver.server.signers;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Properties;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.SignServerException;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SODRequest;
import org.signserver.common.data.SODResponse;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;

/**
 * Test signer returning the content of REQUEST_METADATA in properties file format.
 * This is only indented for internal testing purposes, and is not a real signer.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class EchoRequestMetadataSigner extends BaseSigner {

    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        
        final Properties props = new Properties();
        final int reqId;
        final boolean isSOD;
        final WritableData responseData;
        
        if (signRequest instanceof SignatureRequest) {
            final SignatureRequest req = (SignatureRequest) signRequest;
            reqId = req.getRequestID();
            responseData = req.getResponseData();
            isSOD = false;
        } else if (signRequest instanceof SODRequest) {
            final SODRequest req = (SODRequest) signRequest;
            reqId = req.getRequestID();
            responseData = req.getResponseData();
            isSOD = true;
        } else {
            throw new SignServerException("Unknown sign request");
        }
        
        final Object o = requestContext.get(RequestContext.REQUEST_METADATA);
        
        if (o instanceof RequestMetadata) {
            final RequestMetadata metadata = (RequestMetadata) o;
            
            for (final String key : metadata.keySet()) {
                props.setProperty(key, metadata.get(key));
            }
        }
        
        try (PrintWriter writer = new PrintWriter(responseData.getAsOutputStream())) {
            props.list(writer);
            writer.close();

            if (!isSOD) {
                return new SignatureResponse(reqId, responseData, null, null, null, "text/plain");
            } else {
                return new SODResponse(reqId, responseData, null, null, null, null);            
            }
        } catch (IOException ex) {
            throw new SignServerException("IO error", ex);
        }
    }
    
}
