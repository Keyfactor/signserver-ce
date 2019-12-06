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
package org.signserver.module.mrtdsigner;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.ejb.EJBException;
import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.common.data.ReadableData;
import org.signserver.common.data.LegacyRequest;
import org.signserver.common.data.LegacyResponse;
import org.signserver.common.data.Request;
import org.signserver.common.data.Response;
import org.signserver.common.data.SignatureRequest;
import org.signserver.common.data.SignatureResponse;
import org.signserver.common.data.WritableData;
import org.signserver.server.IServices;
import org.signserver.server.WorkerContext;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoInstance;
import org.signserver.server.cryptotokens.ICryptoTokenV4;
import org.signserver.server.signers.BaseSigner;

/**
 * Class used to sign MRTD Document Objects.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class MRTDSigner extends BaseSigner {

    private static final Logger log = Logger.getLogger(MRTDSigner.class);
    private static final String CONTENT_TYPE = "application/octet-stream";

    private List<String> configErrors;
    
    public MRTDSigner() {
    }
    
    

    @Override
    public void init(int workerId, WorkerConfig config,
            WorkerContext workerContext, EntityManager workerEM) {
        super.init(workerId, config, workerContext, workerEM);
        
        configErrors = new LinkedList<>();
        
        if (hasSetIncludeCertificateLevels) {
            configErrors.add(WorkerConfig.PROPERTY_INCLUDE_CERTIFICATE_LEVELS + " is not supported.");
        }
    }

    /**
     * The main method that signs a number of byte arrays with the algorithm
     * specified for MRTD Security Objects.
     * 
     * 
     * @param signRequest must be of the class MRTDSignRequest
     * @param requestContext
     * @return returns a MRTDSignResponse with the same number of signatures as requested.
     * @throws IllegalRequestException
     * @throws CryptoTokenOfflineException
     * @throws SignServerException
     */
    @Override
    public Response processData(Request signRequest,
            RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {

        if (log.isTraceEnabled()) {
            log.trace(">processData");
        }
        
        if (!configErrors.isEmpty()) {
            throw new SignServerException("Worker is misconfigured");
        }
        
        Response ret = null;

        ICryptoInstance crypto = null;
        try {
            crypto = acquireCryptoInstance(ICryptoTokenV4.PURPOSE_SIGN, signRequest, requestContext);

            if (signRequest instanceof LegacyRequest) {
                MRTDSignRequest req = (MRTDSignRequest) ((LegacyRequest) signRequest).getLegacyRequest();

                ArrayList<byte[]> genSignatures = new ArrayList<>();

                Iterator<?> iterator = ((ArrayList<?>) req.getRequestData()).iterator();
                while (iterator.hasNext()) {

                    byte[] data = null;
                    try {
                        data = (byte[]) iterator.next();
                    } catch (Exception e) {
                        throw new IllegalRequestException("Signature request data must be an ArrayList of byte[]");
                    }

                    genSignatures.add(encrypt(data, signRequest, requestContext, crypto));
                }

                ret = new LegacyResponse(new MRTDSignResponse(req.getRequestID(), genSignatures,
                                           getSigningCertificate(crypto)));

            } else if (signRequest instanceof SignatureRequest) {
                SignatureRequest req = (SignatureRequest) signRequest;
                final ReadableData requestData = req.getRequestData();
                final WritableData responseData = req.getResponseData();
                
                try (OutputStream out = responseData.getAsInMemoryOutputStream()) {
                    byte[] bytes = requestData.getAsByteArray();
                    final String archiveId = createArchiveId(bytes, (String) requestContext.get(RequestContext.TRANSACTION_ID));

                    byte[] signedbytes = encrypt(bytes, signRequest, requestContext, crypto);
                    out.write(signedbytes);

                    final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, responseData.toReadableData(), archiveId));

                    // The client can be charged for the request
                    requestContext.setRequestFulfilledByWorker(true);
                    
                    return new SignatureResponse(req.getRequestID(), responseData,
                                                         getSigningCertificate(crypto),
                                                         archiveId, archivables, CONTENT_TYPE);
                } catch (IOException ex) {
                    throw new SignServerException("IO error", ex);
                }
            } else {
                throw new IllegalRequestException("Unexpected request type: " + signRequest.getClass().getName());
            }
        } finally {
            releaseCryptoInstance(crypto, requestContext);
        }
        if (log.isTraceEnabled()) {
            log.trace("<processData");
        }
        return ret;
    }

    private byte[] encrypt(final byte[] data, final Request request,
                           final RequestContext context, final ICryptoInstance crypto)
            throws CryptoTokenOfflineException, SignServerException, IllegalRequestException {
        Cipher c;
        try {
            // Using a PKCS#11 HSM plain RSA Cipher does not work, but we have to use RSA/ECB/PKCS1Padding
            // It may be possible to use that, if the data is already padded correctly when it is sent as input, but only for 
            // PKCS#1, not PSS. Sun's PKCS#11 provider does not supoprt PSS (OAEP) padding yet as of 2009-08-14.
            // The below (plain RSA) works for soft keystores and PrimeCardHSM
            c = Cipher.getInstance("RSA", crypto.getProvider());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new EJBException(e);
        }

        try {
            c.init(Cipher.ENCRYPT_MODE, crypto.getPrivateKey());
        } catch (InvalidKeyException e) {
            throw new EJBException(e);
        }

        byte[] result;
        try {
            result = c.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new EJBException(e);
        }
        return result;
    }



    @Override
    protected List<String> getFatalErrors(final IServices services) {
        final List<String> errors = super.getFatalErrors(services);
        
        errors.addAll(configErrors);
        return errors;
    }
    
    
}
