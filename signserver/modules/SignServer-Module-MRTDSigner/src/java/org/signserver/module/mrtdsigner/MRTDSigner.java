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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.ejb.EJBException;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.server.archive.Archivable;
import org.signserver.server.archive.DefaultArchivable;
import org.signserver.server.cryptotokens.ICryptoToken;
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

    public MRTDSigner() {
    }

    /**
     * The main method that signs a number of byte arrays with the algorithm
     * specified for MRTD Security Objects.
     * 
     * 
     * @param signRequest must be of the class MRTDSignRequest
     * @return returns a MRTDSignResponse with the same number of signatures as requested.
     *
     */
    public ProcessResponse processData(ProcessRequest signRequest,
            RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException {

        if (log.isTraceEnabled()) {
            log.trace(">processData");
        }
        ProcessResponse ret = null;
      
        final ISignRequest sReq = (ISignRequest) signRequest;

        if (sReq.getRequestData() == null) {
            throw new IllegalRequestException("Signature request data cannot be null.");
        }

        if (signRequest instanceof MRTDSignRequest) {
            MRTDSignRequest req = (MRTDSignRequest) signRequest;

            ArrayList<byte[]> genSignatures = new ArrayList<byte[]>();

            Iterator<?> iterator = ((ArrayList<?>) req.getRequestData()).iterator();
            while (iterator.hasNext()) {

                byte[] data = null;
                try {
                    data = (byte[]) iterator.next();
                } catch (Exception e) {
                    throw new IllegalRequestException("Signature request data must be an ArrayList of byte[]");
                }

                genSignatures.add(encrypt(data));
            }

            ret = new MRTDSignResponse(req.getRequestID(), genSignatures, getSigningCertificate());

        } else if (signRequest instanceof GenericSignRequest) {
            GenericSignRequest req = (GenericSignRequest) signRequest;

            byte[] bytes = req.getRequestData();
            final String archiveId = createArchiveId(bytes, (String) requestContext.get(RequestContext.TRANSACTION_ID));

            byte[] signedbytes = encrypt(bytes);
            final Collection<? extends Archivable> archivables = Arrays.asList(new DefaultArchivable(Archivable.TYPE_RESPONSE, CONTENT_TYPE, signedbytes, archiveId));

            if (signRequest instanceof GenericServletRequest) {
                ret = new GenericServletResponse(sReq.getRequestID(), signedbytes, getSigningCertificate(), archiveId, archivables, CONTENT_TYPE);
            } else {
                ret = new GenericSignResponse(sReq.getRequestID(), signedbytes, getSigningCertificate(), archiveId, archivables);
            }
        } else {
            throw new IllegalRequestException("Sign request with id: " + sReq.getRequestID() + " is of the wrong type: "
                    + sReq.getClass().getName() + " should be MRTDSignRequest or GenericSignRequest");
        }
        if (log.isTraceEnabled()) {
            log.trace("<processData");
        }
        return ret;
    }

    private byte[] encrypt(byte[] data) throws CryptoTokenOfflineException, SignServerException {
        Cipher c;
        try {
            // Using a PKCS#11 HSM plain RSA Cipher does not work, but we have to use RSA/ECB/PKCS1Padding
            // It may be possible to use that, if the data is already padded correctly when it is sent as input, but only for 
            // PKCS#1, not PSS. Sun's PKCS#11 provider does not supoprt PSS (OAEP) padding yet as of 2009-08-14.
            // The below (plain RSA) works for soft keystores and PrimeCardHSM
            c = Cipher.getInstance("RSA", getCryptoToken().getProvider(ICryptoToken.PROVIDERUSAGE_SIGN));
        } catch (NoSuchAlgorithmException e) {
            throw new EJBException(e);
        } catch (NoSuchProviderException e) {
            throw new EJBException(e);
        } catch (NoSuchPaddingException e) {
            throw new EJBException(e);
        }

        try {
            c.init(Cipher.ENCRYPT_MODE, this.getCryptoToken().getPrivateKey(ICryptoToken.PURPOSE_SIGN));
        } catch (InvalidKeyException e) {
            throw new EJBException(e);
        }

        byte[] result;
        try {
            result = c.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            throw new EJBException(e);
        } catch (BadPaddingException e) {
            throw new EJBException(e);
        }
        return result;
    }
}
