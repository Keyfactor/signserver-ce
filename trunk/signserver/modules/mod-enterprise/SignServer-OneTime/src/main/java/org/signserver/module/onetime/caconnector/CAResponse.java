/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
