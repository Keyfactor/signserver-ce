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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Properties;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.SODSignRequest;
import org.signserver.common.SODSignResponse;
import org.signserver.common.SignServerException;

/**
 * Test signer returning the content of REQUEST_METADATA in properties file format.
 * This is only indented for internal testing purposes, and is not a real signer.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class EchoRequestMetadataSigner extends BaseSigner {

    @Override
    public ProcessResponse processData(ProcessRequest signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        
        final Properties props = new Properties();
        final int reqId;
        final boolean isSOD;
        
        if (signRequest instanceof GenericSignRequest) {
            final GenericSignRequest req = (GenericSignRequest) signRequest;
            reqId = req.getRequestID();
            isSOD = false;
        } else if (signRequest instanceof SODSignRequest) {
            final SODSignRequest req = (SODSignRequest) signRequest;
            reqId = req.getRequestID();
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
        
        final StringWriter writer = new StringWriter();
        props.list(new PrintWriter(writer));
        
        if (!isSOD) {
            return new GenericServletResponse(reqId, writer.getBuffer().toString().getBytes(), null, null, null, "text/plain");
        } else {
            return new SODSignResponse(reqId, writer.getBuffer().toString().getBytes(), null, null, null);            
        }
    }
    
}
