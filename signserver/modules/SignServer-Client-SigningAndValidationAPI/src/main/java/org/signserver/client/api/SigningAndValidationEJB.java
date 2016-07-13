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
package org.signserver.client.api;

import javax.naming.NamingException;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GenericValidationRequest;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.ServiceLocator;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.ProcessSessionRemote;

/**
 * Implements ISigningAndValidation using EJB remote interface.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class SigningAndValidationEJB implements ISigningAndValidation {

    private final ProcessSessionRemote processSession;

    /**
     * Creates an instance of SigningAndValidationEJB which lookups the 
     * SignServer interface over remote EJB.
     * 
     * @throws NamingException If an naming exception is encountered.
     */
    public SigningAndValidationEJB() throws NamingException {
        processSession = ServiceLocator.getInstance().lookupRemote(
                ProcessSessionRemote.class);
    }

    @Override
    public GenericSignResponse sign(String signerIdOrName, byte[] xmlDocument) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        GenericSignRequest request = new GenericSignRequest(1, xmlDocument);
        ProcessResponse resp = process(signerIdOrName, request, new RemoteRequestContext());
        if (!(resp instanceof GenericSignResponse)) {
            throw new SignServerException("Unexpected response type: " + resp.getClass().getName());
        }
        return (GenericSignResponse) resp;
    }

    @Override
    public GenericValidationResponse validate(String validatorIdOrName, byte[] xmlDocument) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        ProcessResponse resp = process(validatorIdOrName, new GenericValidationRequest(1, xmlDocument), new RemoteRequestContext());
        if (!(resp instanceof GenericValidationResponse)) {
            throw new SignServerException("Unexpected response type: " + resp.getClass().getName());
        }
        return (GenericValidationResponse) resp;
    }

    @Override
    public ProcessResponse process(String workerIdOrName, ProcessRequest request, RemoteRequestContext context) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        return processSession.process(WorkerIdentifier.createFromIdOrName(workerIdOrName), request, context);
    }
}
