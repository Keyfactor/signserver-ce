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

package org.signserver.server.signtokens;
 
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Properties;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.catoken.IHardCAToken;
import org.ejbca.util.Base64;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.SignTokenAuthenticationFailureException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.SignerStatus;

import se.primeKey.caToken.card.PrimeCAToken;


/**
 * Class used to connect to the PrimeCard HSM card.
 * 
 * @see org.signserver.server.signtokens.ISignToken
 * @author Philip Vendil
 * @version $Id: PrimeCardHSMSignToken.java,v 1.1 2007-02-27 16:18:26 herrvendil Exp $
 */

public class PrimeCardHSMSignToken  implements ISignToken{

	private static Logger log = Logger.getLogger(PrimeCardHSMSignToken.class);
	
	private PrimeCAToken catoken = null;
	
	public PrimeCardHSMSignToken(){
		catoken = new PrimeCAToken();   
		
	}

	/**
	 * Method initializing the primecardHSM device 
	 * 
	 */
	public void init(Properties props) {
	   String signaturealgoritm = props.getProperty(WorkerConfig.SIGNERPROPERTY_SIGNATUREALGORITHM);
	   catoken.init(props, signaturealgoritm);	
	   String authCode = props.getProperty("authCode");
	   if(authCode != null){
		  try{ 
		    this.activate(authCode);
		  }catch(Exception e){
			  throw new EJBException(e);
		  }
	   }
	}

	/**
	 * Method returning SignerStatus.STATUS_ACTIVE if every thing is ok, othervise STATUS_OFFLINE.
	 * 
	 */
	public int getSignTokenStatus() {
        int status = catoken.getCATokenStatus();
        if(status == IHardCAToken.STATUS_ACTIVE){
        	return SignerStatus.STATUS_ACTIVE;
        }        		
		
		return SignerStatus.STATUS_OFFLINE;
	}

	/**
	 * Method activating the PrimeCardHSM using the given key
	 * 
	 * @throws SignTokenAuthenticationFailureException if activation failed, message gives more info
	 * @throws SignTokenOfflineException if connection to token couldnt be created.
	 * 
	 */
	public void activate(String authenticationcode) throws SignTokenAuthenticationFailureException, SignTokenOfflineException {
		try {
			catoken.activate(authenticationcode);
		} catch (CATokenOfflineException e) {
			throw new SignTokenOfflineException(e.getMessage());
		} catch (CATokenAuthenticationFailedException e) {
			throw new SignTokenAuthenticationFailureException(e.getMessage());
		}
		
	}
	
	/**
	 * Method deactivating the PrimeCardHSM token
	 * 
	 * @return true if everything went successful
	 */
	public boolean deactivate() {
		return catoken.deactivate();
	}
	
	/**
	 * Returns a reference to the private key to use.
	 * 
	 * @see org.signserver.server.signtokens.ISignToken 
	 */
	public PrivateKey getPrivateKey(int purpose) throws SignTokenOfflineException {
		try {
			return catoken.getPrivateKey(purpose);
		} catch (CATokenOfflineException e) {
			throw new SignTokenOfflineException(e.getMessage());
		}
	}

	/**
	 * Returns a reference to the public key to use.
	 * 
	 * @see org.signserver.server.signtokens.ISignToken 
	 */
	public PublicKey getPublicKey(int purpose) throws SignTokenOfflineException {
		try {
			return catoken.getPublicKey(purpose);
		} catch (CATokenOfflineException e) {
			throw new SignTokenOfflineException(e.getMessage());
		}	}

	/**
	 * Returns the providername that should be used.
	 */
	public String getProvider() {
       return catoken.getProvider();
	}

	public Certificate getCertificate(int purpose) throws SignTokenOfflineException {
		return null;
	}

	public Collection getCertificateChain(int purpose) throws SignTokenOfflineException {
		return null;
	}

	/**
	 * Method that expects a 
	 */
	public ISignerCertReqData genCertificateRequest(ISignerCertReqInfo info) throws SignTokenOfflineException {
		Base64SignerCertReqData retval = null;
		if(info instanceof PKCS10CertReqInfo){
			PKCS10CertReqInfo reqInfo = (PKCS10CertReqInfo) info; 
			PKCS10CertificationRequest pkcs10;
			try {
				pkcs10 = new PKCS10CertificationRequest(reqInfo.getSignatureAlgorithm(),reqInfo.getSubjectDN(),getPublicKey(PURPOSE_SIGN),reqInfo.getAttributes(),getPrivateKey(PURPOSE_SIGN));
				retval = new Base64SignerCertReqData(Base64.encode(pkcs10.getEncoded()));
			} catch (InvalidKeyException e) {
				log.error(e);
			} catch (NoSuchAlgorithmException e) {
				log.error(e);
			} catch (NoSuchProviderException e) {
				log.error(e);
			} catch (SignatureException e) {
				log.error(e);
			}
						
		}
		return retval;
	}

	
	
	

}
