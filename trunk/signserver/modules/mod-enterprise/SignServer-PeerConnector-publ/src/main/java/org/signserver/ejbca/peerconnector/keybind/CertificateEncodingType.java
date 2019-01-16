/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.ejbca.peerconnector.keybind;

/**
 * Type of encoding for the certificate or certificate chain.
 *
 * @version $Id$
 */
public enum CertificateEncodingType {
    
    /** A single certificate in binary (DER) encoding. */
    BINARY_CERTIFICATE(0),
    
    /** One or more certificates (a certificate chain) in PEM encoding. */
    PEM_CERTIFICATES(1),
    
    // New certificate encoding types can be added here
    
    /** Any other certificate type not yet supported by this implementation. */
    UNKNOWN(-1);
    
    private final int value;

    private CertificateEncodingType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    /**
     * Get the certificate encoding type corresponding to the int value or the UNKNOWN type.
     * @param value the integer value
     * @return the certificate encoding type
     */
    public static CertificateEncodingType fromInt(int value) {
        for (CertificateEncodingType type : CertificateEncodingType.values()) {
            if (type.getValue() == value) {
                return type;
            }
        }
        return CertificateEncodingType.UNKNOWN;
    }
    
}
