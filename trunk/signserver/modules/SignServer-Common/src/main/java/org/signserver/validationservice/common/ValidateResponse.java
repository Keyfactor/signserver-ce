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
package org.signserver.validationservice.common;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestAndResponseManager;

/**
 * ValidateResponse is the response sent back from the validation service
 * containing the status of the validation
 *
 * @author Philip Vendil
 * @version $Id$
 */
public class ValidateResponse extends ProcessResponse {

    private static final long serialVersionUID = 1L;
    
    private Validation validation;
    private String[] validCertificatePurposes;

    /**
     * Default constructor used during serialization
     */
    public ValidateResponse() {
    }

    /**
     * Main constructor.
     * 
     * @param validation of the certificate verified
     * @param validPurposes Valid purposes
     */
    public ValidateResponse(Validation validation, String[] validPurposes) {
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
    public String getValidCertificatePurposes() {
        String retval = null;
        if (validCertificatePurposes != null && validCertificatePurposes.length > 0) {
            retval = validCertificatePurposes[0];
            for (int i = 1; i < validCertificatePurposes.length; i++) {
                retval += "," + validCertificatePurposes[i];
            }
        }
        return retval;
    }

    @Override
    public void parse(DataInput in) throws IOException {
        in.readInt();
        validation = new Validation();
        validation.parse(in);
        int size = in.readInt();
        if (size > 0) {
            this.validCertificatePurposes = new String[size];
            for (int i = 0; i < size; i++) {
                int stringLen = in.readInt();
                byte[] stringData = new byte[stringLen];
                in.readFully(stringData);
                validCertificatePurposes[i] = new String(stringData, StandardCharsets.UTF_8);
            }
        }
    }

    @Override
    public void serialize(DataOutput out) throws IOException {
        out.writeInt(RequestAndResponseManager.RESPONSETYPE_VALIDATE);
        validation.serialize(out);
        if (validCertificatePurposes == null) {
            out.writeInt(0);
        } else {
            out.writeInt(validCertificatePurposes.length);
            for (String validCertificatePurpose : validCertificatePurposes) {
                byte[] stringData = validCertificatePurpose.getBytes(StandardCharsets.UTF_8);
                out.writeInt(stringData.length);
                out.write(stringData);
            }
        }
    }
}
