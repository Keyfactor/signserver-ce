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
package org.signserver.common;

import java.io.IOException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.Strings;
import org.cesecore.util.Base64;

/**
 * Represents a certificate signing request in PKCS#10 format.
 * 
 * Replaces Base64SignerCertReqData.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class Pkcs10CertReqData extends AbstractCertReqData {

    private static final String PEM_PKCS10_HEADER = "-----BEGIN CERTIFICATE REQUEST-----\n";
    private static final String PEM_PKCS10_FOOTER = "\n-----END CERTIFICATE REQUEST-----\n";
    
    private final byte[] data;

    public Pkcs10CertReqData(PKCS10CertificationRequest pkcs10) throws IOException {
        super("application/pkcs10", ".p10");
        this.data = pkcs10.getEncoded();
    }

    @Override
    public String toArmoredForm() throws IOException {
        final StringBuilder result = new StringBuilder();
        result.append(PEM_PKCS10_HEADER);
        result.append(Strings.fromByteArray(Base64.encode(data, true)));
        result.append(PEM_PKCS10_FOOTER);
        return result.toString();
    }

    @Override
    public byte[] toBinaryForm() throws IOException {
        return data;
    }
    
}
