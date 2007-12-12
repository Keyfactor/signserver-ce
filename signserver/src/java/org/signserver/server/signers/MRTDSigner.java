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

package org.signserver.server.signers;
 
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

import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.ISignRequest;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.MRTDSignRequest;
import org.signserver.common.MRTDSignResponse;
import org.signserver.server.RequestContext;
import org.signserver.server.cryptotokens.ICryptoToken;


/**
 * Class used to sign MRTD Document Objects.
 * 
 * @author Philip Vendil
 * @version $Id: MRTDSigner.java,v 1.8 2007-12-12 14:00:06 herrvendil Exp $
 */

public class MRTDSigner extends BaseSigner {
	
	private transient Logger log = Logger.getLogger(this.getClass());
	
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
		if(!(signRequest instanceof MRTDSignRequest)){
			throw new IllegalRequestException("Sign request with id :" + sReq.getRequestID() + " is of the wrong type :" 
					                               + signRequest.getClass().getName() + " should be MRTDSignRequest ");
		}
		
		MRTDSignRequest req = (MRTDSignRequest) signRequest;
		
        ArrayList<byte[]> genSignatures = new ArrayList<byte[]>();
        
		if(req.getRequestData() == null){
			throw new IllegalRequestException("Signature request data cannot be null.");
		}
        
        Iterator<?> iterator = ((ArrayList<?>) req.getRequestData()).iterator();
        while(iterator.hasNext()){
        	
        	byte[] data = null;
        	try{
        	   data = (byte[]) iterator.next();	
        	}catch(Exception e){
        		throw new IllegalRequestException("Signature request data must be an ArrayList of byte[]");
        	}
        	
        	
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


            
            genSignatures.add(result);	
        }
        
		return new MRTDSignResponse(sReq.getRequestID(),genSignatures,getSigningCertificate());
	} 



    /**
     * Not supported yet
     */
	public ICertReqData genCertificateRequest(ISignerCertReqInfo info) throws CryptoTokenOfflineException{
		log.error("Error : genCertificateRequest called for MRTDSigner which isn't supportet yet");
		return null;
	}


	
}
