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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.ejb.EJBException;

import org.signserver.common.ISignRequest;
import org.signserver.common.ISignResponse;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalSignRequestException;
import org.signserver.common.MRTDSignRequest;
import org.signserver.common.MRTDSignResponse;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.server.signtokens.ISignToken;


/**
 * Class used to sign MRTD Document Objects.
 * 
 * @author Philip Vendil
 * @version $Id: MRTDSigner.java,v 1.3 2007-04-12 04:01:12 herrvendil Exp $
 */

public class MRTDSigner extends BaseSigner {
	
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
	
	public ISignResponse signData(ISignRequest signRequest,
	                              X509Certificate cert) throws IllegalSignRequestException, SignTokenOfflineException{
		
		if(!(signRequest instanceof MRTDSignRequest)){
			throw new IllegalSignRequestException("Sign request with id :" + signRequest.getRequestID() + " is of the wrong type :" 
					                               + signRequest.getClass().getName() + " should be MRTDSignRequest ");
		}
		
		MRTDSignRequest req = (MRTDSignRequest) signRequest;
		
        ArrayList genSignatures = new ArrayList();
        
		if(req.getSignRequestData() == null){
			throw new IllegalSignRequestException("Signature request data cannot be null.");
		}
        
        Iterator iterator = ((ArrayList) req.getSignRequestData()).iterator();
        while(iterator.hasNext()){
        	
        	byte[] data = null;
        	try{
        	   data = (byte[]) iterator.next();	
        	}catch(Exception e){
        		throw new IllegalSignRequestException("Signature request data must be an ArrayList of byte[]");
        	}
        	
        	
        	Cipher c;
			try {
				c = Cipher.getInstance("RSA", getSignToken().getProvider(ISignToken.PROVIDERUSAGE_SIGN));
			} catch (NoSuchAlgorithmException e) {
				throw new EJBException(e);
			} catch (NoSuchProviderException e) {
				throw new EJBException(e);
			} catch (NoSuchPaddingException e) {
				throw new EJBException(e);
			}

            try {
				c.init(Cipher.ENCRYPT_MODE, this.getSignToken().getPrivateKey(ISignToken.PURPOSE_SIGN));				
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
        
		return new MRTDSignResponse(signRequest.getRequestID(),genSignatures,getSigningCertificate());
	} 



    /**
     * Not supported yet
     */
	public ISignerCertReqData genCertificateRequest(ISignerCertReqInfo info) throws SignTokenOfflineException{
		log.error("Error : genCertificateRequest called for MRTDSigner which isn't supportet yet");
		return null;
	}


	
}
