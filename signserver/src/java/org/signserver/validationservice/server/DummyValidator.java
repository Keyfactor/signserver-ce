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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

import javax.persistence.EntityManager;

import org.ejbca.util.CertTools;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.validationservice.common.Validation;

/**
 * Dummy validator used for testing and demostration purposes.
 * 
 * @author Philip Vendil
 * 
 * @version $Id: DummyValidator.java,v 1.1 2007-11-28 12:21:49 herrvendil Exp $
 */
public class DummyValidator implements IValidator {
	
	/**
	 * @see org.signserver.validationservice.server.IValidator#init(int, java.util.Properties, javax.persistence.EntityManager, org.signserver.server.cryptotokens.IExtendedCryptoToken)
	 */
	public void init(int workerId, int validatorId, Properties props, EntityManager em,
			ICryptoToken ct) throws SignServerException {
		
		if(props.getProperty("TESTPROP") == null){
			throw new SignServerException("Error property 'TESTPROP' is not set for validator " + validatorId  + " in worker " + workerId);
		}

	}

	/**
	 * @see org.signserver.validationservice.server.IValidator#validate(java.security.cert.Certificate)
	 */
	public Validation validate(Certificate cert)
			throws IllegalRequestException, CryptoTokenOfflineException,
			SignServerException {
		X509Certificate xcert = (X509Certificate) cert;
		if(CertTools.getIssuerDN(xcert).equals("CN=cert1")){
			return new Validation(cert,Validation.STATUS_REVOKED,"This certificate is revoced", new Date(), 3);
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
