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
import java.util.Iterator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.ejb.EJBException;

import org.bouncycastle.util.encoders.Hex;
import org.ejbca.util.CertTools;
import org.signserver.common.ArchiveData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericServletRequest;
import org.signserver.common.GenericServletResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignRequest;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.MRTDSignRequest;
import org.signserver.common.MRTDSignResponse;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestContext;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.signers.BaseSigner;


/**
 * Class used to sign MRTD Document Objects.
 * 
 * @author Philip Vendil
 * @version $Id$
 */

public class MRTDSigner extends BaseSigner {
	
	//private transient Logger log = Logger.getLogger(this.getClass());
	
	public MRTDSigner(){
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
	                              RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException{

            ISignRequest sReq = (ISignRequest) signRequest;

            if(sReq.getRequestData() == null){
                throw new IllegalRequestException("Signature request data cannot be null.");
            }

            if(signRequest instanceof MRTDSignRequest) {
                MRTDSignRequest req = (MRTDSignRequest) signRequest;

                ArrayList<byte[]> genSignatures = new ArrayList<byte[]>();

                Iterator<?> iterator = ((ArrayList<?>) req.getRequestData()).iterator();
                while(iterator.hasNext()){

                    byte[] data = null;
                    try{
                       data = (byte[]) iterator.next();
                    }catch(Exception e){
                            throw new IllegalRequestException("Signature request data must be an ArrayList of byte[]");
                    }

                    genSignatures.add(encrypt(data));
                }

                return new MRTDSignResponse(req.getRequestID(),genSignatures,getSigningCertificate());

            } else if(signRequest instanceof GenericSignRequest) {
                GenericSignRequest req = (GenericSignRequest) signRequest;

                byte[] bytes = req.getRequestData();
		String fp = new String(Hex.encode(CertTools.generateSHA1Fingerprint(bytes)));

                byte[] signedbytes = encrypt(bytes);

                if(signRequest instanceof GenericServletRequest){
                    return new GenericServletResponse(sReq.getRequestID(), signedbytes, getSigningCertificate(), fp, new ArchiveData(signedbytes), "application/octet-stream");
                } else {
                    return new GenericSignResponse(sReq.getRequestID(), signedbytes, getSigningCertificate(), fp, new ArchiveData(signedbytes));
                }
            } else {
                throw new IllegalRequestException("Sign request with id: " + sReq.getRequestID() + " is of the wrong type: "
                                                                   + sReq.getClass().getName() + " should be MRTDSignRequest or GenericSignRequest");
            }
	} 



    /**
     * Not supported yet
     */
	public ICertReqData genCertificateRequest(ISignerCertReqInfo info) throws CryptoTokenOfflineException{		
		return getCryptoToken().genCertificateRequest(info);
	}


        private byte[] encrypt(byte[] data) throws CryptoTokenOfflineException {
            Cipher c;
            try {
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
