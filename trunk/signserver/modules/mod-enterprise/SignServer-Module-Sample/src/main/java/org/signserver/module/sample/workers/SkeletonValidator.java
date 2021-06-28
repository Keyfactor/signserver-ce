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
package org.signserver.module.sample.workers;

import java.security.cert.Certificate;
import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IValidationRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.CertificateValidationResponse;
import org.signserver.common.data.DocumentValidationRequest;
import org.signserver.common.data.DocumentValidationResponse;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.validators.BaseValidator;
import org.signserver.validationservice.common.Validation;

/**
 * Skeleton validator...
 * <p>
 * The document validator has the following worker properties:
 * </p>
 * <ul>
 *    <li>
 *       <b>PROPERTY_NAME...</b> = Description...
 *       (Optional/required, default: ...)
 *    </li>
 * </ul>
 * @author ...
 * @see TextSigner
 * @version $Id$
 */
public class SkeletonValidator extends BaseValidator {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SkeletonValidator.class);

    // Worker properties
    //...

    // Log fields
    //...

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    //...

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);

        // Read properties
        //...
    }

    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException,
            CryptoTokenOfflineException, SignServerException {
        
        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }
        if (!(signRequest instanceof DocumentValidationRequest)) {
            throw new IllegalRequestException("Unexpected request type");
        }
        final IValidationRequest request = (IValidationRequest) signRequest;

        if (!(request.getRequestData() instanceof byte[])) {
            throw new IllegalRequestException(
                    "Unexpected request data type");
        }

        // Get the data from request
        final byte[] data = (byte[]) request.getRequestData();
        //...        

        // We will charge the client regardless of the outcome of the
        // validation
        requestContext.setRequestFulfilledByWorker(true);

        // Check signature
        Certificate cert = null; //...
        boolean validSignature = false; //...

        // Check certificate and chain
        List<Certificate> certChain = null; //...
        boolean validCertificate = false; //...
        Validation v = new Validation(cert, certChain,
                Validation.Status.DONTVERIFY,
                "Certificate validation failed");

        // Log anything interesting from the request to the worker logger
        //...

        // Return the response
        return new DocumentValidationResponse(request.getRequestID(),
                validSignature && validCertificate,
                new CertificateValidationResponse(v, null));
    }

    @Override
    protected List<String> getFatalErrors(final IServices services) {
        // Add our errors to the list of errors
        final LinkedList<String> errors = new LinkedList<>(
                super.getFatalErrors(services));
        errors.addAll(configErrors);
        return errors;
    }

}
