package org.signserver.module.pdfsigner;

import java.math.BigInteger;

import org.apache.log4j.Logger;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.ejb.interfaces.IInternalWorkerSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.UsernamePasswordClientCredential;

import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.TSAClient;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.tsp.*;

public class InternalTSAClient implements TSAClient {
    private static Logger LOG = Logger.getLogger(InternalTSAClient.class);
    
    private IInternalWorkerSession session;
    private String workerNameOrId;
    private String username;
    private String password;
    private int tokenSizeEstimated = 7168;
    
    public InternalTSAClient(final IInternalWorkerSession session, final String workerNameOrId,
            final String username, final String password) {
        this.session = session;
        this.workerNameOrId = workerNameOrId;
        this.username = username;
        this.password = password;
    }
    
    @Override
    public int getTokenSizeEstimate() {
        return tokenSizeEstimated;
    }

    @Override
    public byte[] getTimeStampToken(PdfPKCS7 caller, byte[] imprint)
            throws Exception {
        int workerId;
        try {
            workerId = Integer.parseInt(workerNameOrId);
        } catch (NumberFormatException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Not a workerId, maybe workerName: " + workerNameOrId);
            }
            workerId = session.getWorkerId(workerNameOrId);
        }
        
        // Setup the time stamp request
        TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
        tsqGenerator.setCertReq(true);

        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        TimeStampRequest request = tsqGenerator.generate(X509ObjectIdentifiers.id_SHA1, imprint, nonce);
        byte[] requestBytes = request.getEncoded();

        final RequestContext context = new RequestContext();
        
        if (username != null && password != null) {
            context.put(RequestContext.CLIENT_CREDENTIAL,
                    new UsernamePasswordClientCredential(username, password));
        }
        
        final ProcessResponse resp = session.process(workerId, new GenericSignRequest(hashCode(), requestBytes), context);
    
        if (resp instanceof GenericSignResponse) {
            final byte[] respBytes = ((GenericSignResponse) resp).getProcessedData();
        
            TimeStampResponse response = new TimeStampResponse(respBytes);
            
            TimeStampToken  tsToken = response.getTimeStampToken();
            if (tsToken == null) {
                throw new SignServerException("TSA '" + workerNameOrId + "' failed to return time stamp token: " + response.getStatusString());
            }

            byte[] encoded = tsToken.getEncoded();
            tokenSizeEstimated = encoded.length;

            return encoded;
        } else {
            throw new SignServerException("Unknown response");
        }
        
    }

}
