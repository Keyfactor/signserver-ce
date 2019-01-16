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
package org.signserver.validationservice.server;

import javax.persistence.EntityManager;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerStatusInfo;
import org.signserver.common.data.CertificateValidationRequest;
import org.signserver.common.data.CertificateValidationResponse;
import org.signserver.server.IServices;

/**
 * Interface all Validation Services have to implement.
 * 
 * It's recommended that all implementing classes instead inherits
 * the BaseValidationService.
 * 
 * It have one main method
 *  validate                 : Main method used to validate a certificate.
 *  
 * @author Philip Vendil 13 nov 2007
 * @version $Id$
 */
public interface IValidationService {

    /**
     * Initialization method that should be called directly after creation.
     * @param workerId the unique id of the worker
     * @param config the configuration stored in database
     * @param em reference to the entity manager
     */
    void init(int workerId, WorkerConfig config, EntityManager em);

    /**
     * Method used to check the validation of a certificate
     * 
     * @param validationRequest
     * @return a ValidateResponse
     * @throws IllegalRequestException if data in the request didn't conform with the specification.
     * @throws CryptoTokenOfflineException if the crypto token isn't online. 
     * @throws SignServerException for general failure exception during validation
     * @see org.signserver.validationservice.common.ValidateRequest
     * @see org.signserver.validationservice.common.ValidateResponse
     */
    CertificateValidationResponse validate(CertificateValidationRequest validationRequest) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;

    /**
     * Should return the actual status of the service, status could be if
     * the signer is activated or not, or equivalent for a service.
     * @param services Services for implementations to use
     * @return a WorkerStatus object.
     */
    WorkerStatusInfo getStatus(IServices services);
}
