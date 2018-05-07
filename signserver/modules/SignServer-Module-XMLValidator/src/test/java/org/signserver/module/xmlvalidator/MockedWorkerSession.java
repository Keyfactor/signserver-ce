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
package org.signserver.module.xmlvalidator;

import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.CertificateValidationRequest;
import org.signserver.common.data.CertificateValidationResponse;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.ejb.interfaces.ProcessSessionLocal;
import org.signserver.server.log.AdminInfo;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.ValidationServiceConstants;

/**
 * Mocked version of WorkerSession only implementing the process method
 * and using a CertValidator.
 *
 * @author Markus Kilås
 * @version $Id: MockedXAdESSigner.java 4704 2014-05-16 12:38:10Z netmackan $
 */
public class MockedWorkerSession implements ProcessSessionLocal, InternalProcessSessionLocal {

    @Override
    public Response process(AdminInfo admin, WorkerIdentifier workerId, Request request, RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        CertificateValidationRequest vr = (CertificateValidationRequest) request;
        String[] validPurposes = new String[] { ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE };

        Certificate icert = vr.getCertificate();
        List<Certificate> chain = Arrays.asList(icert);

        return new CertificateValidationResponse(new Validation(icert, chain, Validation.Status.VALID, "Certificate is valid"), validPurposes);
    }
    
}
