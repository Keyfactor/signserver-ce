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
package org.signserver.validationservice.server;

import java.net.ConnectException;
import java.util.Date;
import java.util.Properties;

import javax.persistence.EntityManager;

import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.X509Certificate;

/**
 * Dummy validator used for testing and demonstration purposes.
 * 
 * @author Philip Vendil
 * 
 * @version $Id: DummyValidator.java,v 1.3 2007-12-04 15:31:27 herrvendil Exp $
 */
public class DummyValidator extends BaseValidator {
	
	long waitTime = 0;
	
	/**
	 * @see org.signserver.validationservice.server.IValidator#init(int, java.util.Properties, javax.persistence.EntityManager, org.signserver.server.cryptotokens.IExtendedCryptoToken)
	 */
	public void init(int workerId, int validatorId, Properties props, EntityManager em,
			ICryptoToken ct) throws SignServerException {
		super.init(workerId, validatorId, props, em, ct);
		
		if(props.getProperty("TESTPROP") == null){
			throw new SignServerException("Error property 'TESTPROP' is not set for validator " + validatorId  + " in worker " + workerId);
		}
		
		if(props.getProperty("WAITTIME") != null){
			waitTime = Long.parseLong(props.getProperty("WAITTIME"));
		}

	}

	/**
	 * @see org.signserver.validationservice.server.IValidator#validate(java.security.cert.Certificate)
	 */
	public Validation validate(ICertificate cert)
			throws IllegalRequestException, CryptoTokenOfflineException,
			SignServerException {
		
		try {
			Thread.sleep(waitTime);
		} catch (InterruptedException e) {
			
		}
		
		if(getCertificateChain(cert) == null && ((X509Certificate) cert).getBasicConstraints() == -1){
			return null;
		}
		
		X509Certificate xcert = (X509Certificate) cert;
		if(xcert.getIssuer().equals("CN=cert1")){
			return new Validation(cert,getCertificateChain(cert),Validation.Status.REVOKED,"This certificate is revoced", new Date(), 3);
		}
		if(xcert.getSubject().equals("CN=revocedRootCA1")){
			return new Validation(cert,getCertificateChain(cert),Validation.Status.REVOKED,"This certificate is revoced", new Date(), 3);
		}
		if(xcert.getIssuer().equals("CN=revocedRootCA1")){
			return new Validation(cert,getCertificateChain(cert),Validation.Status.CAREVOKED,"This certificate is valid", new Date(), 3);
		}
		if(cert.getSubject().equals("CN=revokedCert1")){
			return new Validation(cert,getCertificateChain(cert),Validation.Status.REVOKED,"This certificate is revoced", new Date(), 3);
		}
		if(cert.getSubject().equals("CN=ValidRootCA1")){
			return new Validation(cert,getCertificateChain(cert),Validation.Status.VALID,"This certificate is valid");
		}
		if(cert.getSubject().equals("CN=ValidSubCA1")){
			return new Validation(cert,getCertificateChain(cert),Validation.Status.VALID,"This certificate is valid");
		}
		if(cert.getIssuer().equals("CN=ValidSubCA1")){
			return new Validation(cert,getCertificateChain(cert),Validation.Status.VALID,"This certificate is valid");
			
		}
		if(cert.getSubject().equals("CN=ValidSubCA2")  && validatorId == 2){
			return new Validation(cert,getCertificateChain(cert),Validation.Status.VALID,"This certificate is valid");
		}	
		if(cert.getSubject().equals("CN=ValidSubSubCA2")  && validatorId == 2){
			return new Validation(cert,getCertificateChain(cert),Validation.Status.VALID,"This certificate is valid");
		}	
		if(cert.getSubject().equals("CN=ValidSubSubSubCA2")  && validatorId == 2){
			return new Validation(cert,getCertificateChain(cert),Validation.Status.VALID,"This certificate is valid");
		}	
		if(cert.getSubject().equals("CN=ValidSubSubSubSubCA2")  && validatorId == 2){
			return new Validation(cert,getCertificateChain(cert),Validation.Status.VALID,"This certificate is valid");
		}	
		if(cert.getIssuer().equals("CN=ValidSubSubSubSubCA2") && validatorId == 2){
			return new Validation(cert,getCertificateChain(cert),Validation.Status.VALID,"This certificate is valid");
		}		
		
		
		return null;
	}

	/**
	 * @see org.signserver.validationservice.server.IValidator#testConnection()
	 */
	public void testConnection() throws ConnectException, SignServerException {
		// Do nothing
	}
	
}
