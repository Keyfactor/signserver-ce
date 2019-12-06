/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.utils.timestampers;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.encoders.Base64;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.data.SignatureRequest;
import org.signserver.ejb.interfaces.InternalProcessSessionLocal;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.data.impl.ByteArrayReadableData;
import org.signserver.server.data.impl.CloseableReadableData;
import org.signserver.server.data.impl.CloseableWritableData;
import org.signserver.server.data.impl.TemporarlyWritableData;
import org.signserver.server.log.AdminInfo;

/**
 * Helper methods used for timestamping.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class TimestampHelper {
    static byte[] fetchTimestampInternal(byte[] request,
                                                          String workerNameOrId,
                                                          String username,
                                                          String password,
                                                          int hashCode,
                                                          InternalProcessSessionLocal workerSession,
                                                          File fileRepository)
        throws IOException, IllegalRequestException, CryptoTokenOfflineException, SignServerException {
        try (
            CloseableReadableData requestData = new ByteArrayReadableData(request, fileRepository);
            CloseableWritableData responseData = new TemporarlyWritableData(false, fileRepository);
        ) {
            final RequestContext context = new RequestContext();

            if (username != null && password != null) {
                final UsernamePasswordClientCredential cred
                        = new UsernamePasswordClientCredential(username, password);
                context.put(RequestContext.CLIENT_CREDENTIAL, cred);
                context.put(RequestContext.CLIENT_CREDENTIAL_PASSWORD, cred);
            }

            workerSession.process(new AdminInfo("Client user", null, null), WorkerIdentifier.createFromIdOrName(workerNameOrId), new SignatureRequest(hashCode, requestData, responseData), context);

            return responseData.toReadableData().getAsByteArray();
        } catch (IllegalRequestException | CryptoTokenOfflineException |
                 SignServerException ex) {
            throw new IOException(ex);
        }
    }
    
    static byte[] fetchTimestampExternal(byte[] request,
                                                 URL tsaurl,
                                                 String basicAuthorization,
                                                 String contentType,
                                                 String acceptType)
        throws IOException, CMSException {
        HttpURLConnection conn = (HttpURLConnection) tsaurl.openConnection();
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setUseCaches(false);
        conn.setRequestMethod("POST");
        if (basicAuthorization != null) {
            conn.setRequestProperty("Authorization", "Basic " + basicAuthorization);
        }
        conn.setRequestProperty("Content-type", contentType);
        conn.setRequestProperty("Content-length", String.valueOf(request.length));
        conn.setRequestProperty("Accept", acceptType);
        conn.setRequestProperty("User-Agent", "Transport");

        conn.getOutputStream().write(request);
        conn.getOutputStream().flush();

        if (conn.getResponseCode() >= 400) {
            throw new IOException("Unable to complete the timestamping due to HTTP error: " + conn.getResponseCode() + " - " + conn.getResponseMessage());
        }

        InputStream in = conn.getInputStream();
        ByteArrayOutputStream bout = new ByteArrayOutputStream();

        byte[] buffer = new byte[4096];
        int n;
        while ((n = in.read(buffer)) != -1) {
            bout.write(buffer, 0, n);
        }

        byte[] response = bout.toByteArray();

        return response;
    }
    
    static CMSSignedData responseToAuthcodeTimestamp(byte[] response) throws CMSException {
        return new CMSSignedData(Base64.decode(response));
    }
    
    static CMSSignedData responseToRFCTimestamp(byte[] response,
            TimeStampRequest req) throws TSPException, IOException {
        TimeStampResp resp = TimeStampResp.getInstance(response);
        TimeStampResponse tsr = new TimeStampResponse(resp);
        tsr.validate(req);
        if (tsr.getStatus() != 0) {
            throw new IOException("Unable to complete the timestamping due to an invalid response (" + tsr.getStatusString() + ")");
        }

        return tsr.getTimeStampToken().toCMSSignedData();
    }
    
    /**
     * Modified version of modifySignedData from jsign's Timestamper implementation.
     * This implementation avoids assuming the content is an instance of ASN1Sequence.
     * This method modifies the sigData parameter.
     *
     * @param sigData Original signed data (without changed unsigned attributes)
     * @param unsignedAttributes Unsigned attributes to substitute
     * @return Modified CMSSignedData with the unsigned attributes substituted
     * @throws IOException
     * @throws CMSException 
     */
    static CMSSignedData addCounterSignatureForTimestamp(final CMSSignedData sigData, final AttributeTable unsignedAttributes)
        throws IOException, CMSException {
        SignerInformation signerInformation = sigData.getSignerInfos().getSigners().iterator().next();
        signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);

        return CMSSignedData.replaceSigners(sigData, new SignerInformationStore(signerInformation));
    }
}
