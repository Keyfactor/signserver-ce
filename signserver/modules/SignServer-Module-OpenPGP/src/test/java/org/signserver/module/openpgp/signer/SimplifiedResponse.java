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
package org.signserver.module.openpgp.signer;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;

/**
 * Holder for the response data and certificate to simplify migration of the
 * unit tests that was designed for the old API.
 *
 * @author Markus Kilås
 * @version $Id$
 */
class SimplifiedResponse {
    
    private final byte[] processedData;
    private final PGPSignature signature;
    private final PGPPublicKey publicKey;

    public SimplifiedResponse(byte[] processedData, PGPSignature signature, PGPPublicKey signerCertificate) {
        this.processedData = processedData;
        this.signature = signature;
        this.publicKey = signerCertificate;
    }

    public byte[] getProcessedData() {
        return processedData;
    }

    public PGPSignature getSignature() {
        return signature;
    }

    public PGPPublicKey getPublicKey() {
        return publicKey;
    }
    
}
