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
package org.signserver.server.archive.test1archiver;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import org.apache.log4j.Logger;
import org.signserver.common.ArchiveData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.RequestMetadata;
import org.signserver.common.SignServerException;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.olddbarchiver.ArchiveDataArchivable;
import org.signserver.server.signers.BaseSigner;

/**
 * A signer used by system tests to test the Archiving API and others. Not usable 
 * in production.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class Test1Signer extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(Test1Signer.class);
    
    public static final String METADATA_FAILREQUEST = "DO_FAIL_REQUEST";

    @Override
    public Response processData(final Request processRequest,
            final RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        LOG.debug(">processData");
        
        final Response result;
        final SignatureRequest request;
        
        if (processRequest instanceof SignatureRequest) {
            request = (SignatureRequest) processRequest;
        } else {
            throw new IllegalRequestException("Unexpeted request type: "
                    + processRequest.getClass());
        }
        final WritableData responseData = request.getResponseData();
        
        try (OutputStream out = responseData.getAsOutputStream()) {
            out.write("SIGNED".getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            throw new SignServerException("IO error", ex);
        }
        
        String archiveId = String.valueOf(request.getRequestID()) + "-" + System.currentTimeMillis();
        try {
            result = new SignatureResponse(((SignatureRequest) request).getRequestID(),
                    responseData, getSigningCertificate(requestContext.getServices()),
                    archiveId,
                    Collections.singletonList(new ArchiveDataArchivable(archiveId, new ArchiveData(responseData.toReadableData().getAsByteArray()), Archivable.TYPE_RESPONSE)), "text/plain");
        } catch (IOException ex) {
            throw new SignServerException("IO error", ex);
        }
        
        // Setting REQUEST_METADATA.DO_FAIL_REQUEST causes this signer to not treat the request as fulfilled
        boolean success = RequestMetadata.getInstance(requestContext).get(METADATA_FAILREQUEST) == null;
        requestContext.setRequestFulfilledByWorker(success);
        
        LOG.debug("<processData");
        return result;
    }
}
