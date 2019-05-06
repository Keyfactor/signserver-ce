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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;

/**
 * Represents an OpenPGP public key in a form that is the same as for
 * certificate signing requests in SignServer.
 * 
 * Purpose of this class it to be able to re-use the Generate CSR functionality
 * also with OpenPGP.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class OpenPgpCertReqData extends AbstractCertReqData {

    private final byte[] data;

    public OpenPgpCertReqData(PGPPublicKey publicKey) throws IOException {
        super("application/pgp-keys", ".asc");
        final ByteArrayOutputStream bout = new ByteArrayOutputStream();
        publicKey.encode(bout);
        this.data = bout.toByteArray();
    }
    
    public OpenPgpCertReqData(PGPSignature sig) throws IOException {
        super("application/pgp-keys", ".asc");
        final ByteArrayOutputStream bout = new ByteArrayOutputStream();
        sig.encode(bout);
        this.data = bout.toByteArray();
    }

    @Override
    public String toArmoredForm() throws IOException {
        final ByteArrayOutputStream bout = new ByteArrayOutputStream();
        try (final ArmoredOutputStream armOut = new ArmoredOutputStream(bout)) {
            final BCPGOutputStream bOut = new BCPGOutputStream(armOut);
            bOut.write(data);
        }
        return new String(bout.toByteArray(), StandardCharsets.UTF_8);
    }

    @Override
    public byte[] toBinaryForm() throws IOException {
        return data;
    }
}
