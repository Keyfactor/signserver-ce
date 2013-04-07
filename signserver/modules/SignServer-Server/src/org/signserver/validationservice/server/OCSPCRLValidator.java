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

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import org.signserver.common.SignServerException;

/**
 * OCSP fail over to CRL validator.
 * 
 * this class overrides the addCertPathCheckers to use OCSPCRLPathChecker instead of OCSP Path Checker used in OCSP Validator
 * also getLogger() is overriden too for proper logging
 * 
 * @author rayback2
 * @version $Id$
 */
public class OCSPCRLValidator extends OCSPValidator {

    /**
     * override the ocsp validators path checker with ocspcrl pathchecker
     */
    @Override
    protected void addCertPathCheckers(Certificate cert,
            PKIXParameters params, Certificate rootCert)
            throws SignServerException, CertificateException, IOException {
        params.addCertPathChecker(new OCSPCRLPathChecker((X509Certificate) rootCert, this.props, getIssuerAuthorizedOCSPResponderCertificates(cert), getIssuerCRLPaths(cert)));
    }
}
