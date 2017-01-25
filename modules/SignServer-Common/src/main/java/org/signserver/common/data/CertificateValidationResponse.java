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
package org.signserver.common.data;

import org.signserver.validationservice.common.Validation;

/**
 * Data holder for a certificate validation response.
 *
 * @version $Id$
 */
public class CertificateValidationResponse extends Response {

    private final Validation validation;
    private final String[] validCertificatePurposes;
    
    /**
     * Main constructor.
     * 
     * @param validation of the certificate verified
     * @param validPurposes Valid purposes
     */
    public CertificateValidationResponse(Validation validation, String[] validPurposes) {
        super();
        this.validation = validation;
        this.validCertificatePurposes = validPurposes;
    }

    /**
     * Get validation.
     * 
     * @return The validation of the requested certificate
     */
    public Validation getValidation() {
        return validation;
    }

    /**
     * Get the purposes of validation.
     * 
     * @return a String with all valid certificate purposes separated by a ','.
     */
    public String getValidCertificatePurposesString() {
        String retval = null;
        if (validCertificatePurposes != null && validCertificatePurposes.length > 0) {
            retval = validCertificatePurposes[0];
            for (int i = 1; i < validCertificatePurposes.length; i++) {
                retval += "," + validCertificatePurposes[i];
            }
        }
        return retval;
    }

    public String[] getValidCertificatePurposes() {
        return validCertificatePurposes;
    }
    
}
