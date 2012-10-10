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

import java.net.ConnectException;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Properties;
import javax.persistence.EntityManager;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.Validation;

/**
 * Interface all types of validators should implement, this could be 
 * a OCSP Validator or CRL validator or simply a database were the certificate
 * status is lookup up. It's recommended that the BaseValidator is inherited.
 * 
 * It's main method is validate(Certificate cert)
 * 
 * Important a validator also have to support to check the revocation status of the
 * involved CA certificates and should only return Validation object with status REVOKED or VALID
 * 
 * @author Philip Vendil
 *  
 * @version $Id$
 *
 */
public interface IValidator {

    /**
     * Initialization method that should be called directly after creation.
     * @param workerId the unique id of the worker
     * @param validatorId the id of this validator, a positive integer.
     * @param props a subset of the worker properties only containing this validators properties, 
     * for instance worker1.val1.propkey will show up as property key 'propkey' in this properies
     * @param em reference to the entity manager
     * @param ct the extended crypto token used by the validation service.
     * @throws SignServerException if unexpected error occurred during initialization.
     */
    void init(int workerId, int validatorId, Properties props, EntityManager em, ICryptoToken ct) throws SignServerException;

    /**
     * Main method of a Validation Service responsible for validating certificates.
     * 
     * Important a validator also have to support to check the revocation status of the
     * involved CA certificates and should only return Validation object with status REVOKED or VALID
     * If the validator doesn't support the given issuer it must return null.
     * 
     * 
     * @param cert the certificate to validate.
     * @return a Validation object or null if the certificate couldn't be looked up in this validator.
     * @throws IllegalRequestException if data in the request didn't conform with the specification.
     * @throws CryptoTokenOfflineException if the crypto token isn't online. 
     * @throws SignServerException for general failure exception during validation.
     */
    Validation validate(Certificate cert) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;

    /**
     * Optional method used to test the connection to a specific underlying validator implementation.
     * 
     * @throws ConnectException if connection to underlying validator implementation failed.
     * @throws SignServerException for general failure exception during validation.
     */
    void testConnection() throws ConnectException, SignServerException;

    /**
     * Method that should return the entire certificate chain for the given certificate
     * or null if the validator doesn't support the issuer of the given certificate.
     * @param certificate to verify
     * @return a certificate chain with the root CA last or null if validator doesn't support given issuer.
     */
    List<Certificate> getCertificateChain(Certificate cert);
}
