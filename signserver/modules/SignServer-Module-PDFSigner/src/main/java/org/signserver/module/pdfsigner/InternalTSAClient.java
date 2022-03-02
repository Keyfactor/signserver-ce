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
package org.signserver.module.pdfsigner;

import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.TSAClient;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.tsp.TimeStampToken;
import org.signserver.common.WorkerIdentifier;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.server.tsa.InternalTimeStampTokenFetcher;

/**
 * TSA Client fetching the token internally.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class InternalTSAClient implements TSAClient {

    private final InternalTimeStampTokenFetcher fetcher;

    private int tokenSizeEstimated = 7168;
    private ASN1ObjectIdentifier digestAlgorithm;

    public InternalTSAClient(final InternalProcessSessionLocal session, final WorkerIdentifier wi,
            final String username, final String password,
            final ASN1ObjectIdentifier digestAlgorithm) {
        this.fetcher = new InternalTimeStampTokenFetcher(session, wi, username, password);
        this.digestAlgorithm = digestAlgorithm;
    }

    @Override
    public int getTokenSizeEstimate() {
        return tokenSizeEstimated;
    }

    @Override
    public byte[] getTimeStampToken(PdfPKCS7 caller, byte[] imprint)
            throws Exception {
        final TimeStampToken token = fetcher.fetchToken(imprint, digestAlgorithm, null);
        final byte[] encoded = token.getEncoded();
        tokenSizeEstimated = encoded.length;
        return encoded;
    }

    @Override
    public MessageDigest getMessageDigest() throws GeneralSecurityException {
        return MessageDigest.getInstance(digestAlgorithm.toString(), "BC");
    }

}
