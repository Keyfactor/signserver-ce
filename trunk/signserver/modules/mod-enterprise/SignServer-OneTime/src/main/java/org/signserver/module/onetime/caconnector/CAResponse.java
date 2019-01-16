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
package org.signserver.module.onetime.caconnector;

import java.util.List;
import org.bouncycastle.cert.X509CertificateHolder;

/**
 * Class representing certificate request response from a CA.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class CAResponse {
    
    private final X509CertificateHolder cert;
    private final List<X509CertificateHolder> certificateChain;
    private final String error;

    /**
     * Constructor creating a successful CA response.
     * 
     * @param cert Issued certificate
     * @param certificateChain Full certificate chain of issued certificate
     */
    public CAResponse(X509CertificateHolder cert, List<X509CertificateHolder> certificateChain) {
        this.cert = cert;
        this.certificateChain = certificateChain;
        this.error = null;
    }

    /**
     * Constructor creating a CA response representing an error.
     * 
     * @param error Error message
     */
    public CAResponse(String error) {
        this.cert = null;
        this.certificateChain = null;
        this.error = error;
    }
    
    public X509CertificateHolder getCert() {
        return cert;
    }

    public List<X509CertificateHolder> getCertificateChain() {
        return certificateChain;
    }

    public String getError() {
        return error;
    }
}
