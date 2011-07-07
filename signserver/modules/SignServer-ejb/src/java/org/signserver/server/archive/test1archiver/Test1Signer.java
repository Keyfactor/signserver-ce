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


import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.ArchiveData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.server.WorkerContext;
import org.signserver.server.signers.BaseSigner;

/**
 * A signer used by system tests to test the Archiving API. Not usable 
 * in production.
 * 
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Test1Signer extends BaseSigner {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(Test1Signer.class);

    
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final WorkerContext workerContext, final EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
    }

    @Override
    public ProcessResponse processData(final ProcessRequest processRequest,
            final RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {

        final ProcessResponse result;
        final GenericSignRequest request;
        
        if (processRequest instanceof GenericSignRequest) {
            request = (GenericSignRequest) processRequest;
        } else {
            throw new IllegalRequestException("Unexpeted request type: "
                    + processRequest.getClass());
        }
        
        final byte[] signedbytes = "SIGNED".getBytes();
        
        result = new GenericSignResponse(request.getRequestID(),
                signedbytes, getSigningCertificate(), 
                String.valueOf(request.getRequestID()) + "-" + System.currentTimeMillis(),
                new ArchiveData(signedbytes));
        return result;
    }
}
