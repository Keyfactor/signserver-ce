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
package org.signserver.server.tsa;

import java.math.BigInteger;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.server.UsernamePasswordClientCredential;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.SignatureRequest;
import org.signserver.server.data.impl.ByteArrayReadableData;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.data.impl.TemporarlyWritableData;
import org.signserver.server.data.impl.UploadConfig;
import org.signserver.server.log.AdminInfo;

/**
 * Fetching time-stamp tokens internally using the internal worker session.
 *
 * @author Marcus Lundblad
 * @author Markus Kilås
 * @version $Id$
 */
public class InternalTimeStampTokenFetcher {

    private static final Logger LOG = Logger.getLogger(InternalTimeStampTokenFetcher.class);

    private final InternalProcessSessionLocal session;
    private final WorkerIdentifier wi;
    private final String username;
    private final String password;

    public InternalTimeStampTokenFetcher(final InternalProcessSessionLocal session, final WorkerIdentifier wi,
            final String username, final String password) {
        this.session = session;
        this.wi = wi;
        this.username = username;
        this.password = password;
    }

    public TimeStampToken fetchToken(byte[] imprint, ASN1ObjectIdentifier digestOID, ASN1ObjectIdentifier reqPolicy) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException, TSPException, IOException {
        // Setup the time stamp request
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.setCertReq(true);

        if (reqPolicy != null) {
            tsqGenerator.setReqPolicy(reqPolicy);
        }

        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        TimeStampRequest request = tsqGenerator.generate(digestOID, imprint, nonce);
        byte[] requestBytes = request.getEncoded();
        final UploadConfig uploadConfig = new UploadConfig();
        try (
                CloseableReadableData requestData = new ByteArrayReadableData(requestBytes, uploadConfig.getRepository());
                CloseableWritableData responseData = new TemporarlyWritableData(false, uploadConfig.getRepository());
            ) {

            final RequestContext context = new RequestContext();

            if (username != null && password != null) {
                UsernamePasswordClientCredential cred
                        = new UsernamePasswordClientCredential(username, password);
                context.put(RequestContext.CLIENT_CREDENTIAL, cred);
                context.put(RequestContext.CLIENT_CREDENTIAL_PASSWORD, cred);
            }

            session.process(new AdminInfo("Client user", null, null),
                    wi, new SignatureRequest(hashCode(), requestData, responseData), context);

            final byte[] respBytes = responseData.toReadableData().getAsByteArray();
            TimeStampResponse response = new TimeStampResponse(respBytes);

            TimeStampToken  tsToken = response.getTimeStampToken();
            if (tsToken == null) {
                throw new SignServerException("TSA '" + wi + "' failed to return time stamp token: " + response.getStatusString());
            }

            if(response.getStatus() != PKIStatus.GRANTED && response.getStatus() != PKIStatus.GRANTED_WITH_MODS) {
                throw new SignServerException("Time stamp token not granted: " + response.getStatusString());
            }
            response.validate(request);

            return tsToken;
        }
    }

}
