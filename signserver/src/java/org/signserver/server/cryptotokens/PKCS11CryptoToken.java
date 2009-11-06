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

package org.signserver.server.cryptotokens;
 
import java.util.Properties;


import org.apache.log4j.Logger;
import org.ejbca.core.model.ca.catoken.PKCS11CAToken;
import org.signserver.common.WorkerConfig;


/**
 * Class used to connect to a PKCS11 HSM.
 * 
 * Properties:
 *   sharedLibrary
 *   slot
 *   defaultKey
 *   pin
 * 
 * 
 * @see org.signserver.server.cryptotokens.ICryptoToken
 * @author Tomas Gustavsson, Philip Vendil
 * @version $Id$
 */

public class PKCS11CryptoToken extends CryptoTokenBase implements ICryptoToken{

	private static final Logger log = Logger.getLogger(PKCS11CryptoToken.class);
	
	public PKCS11CryptoToken() throws InstantiationException{
		catoken = new PKCS11CAToken(); 
	}

	/**
	 * Method initializing the PKCS11 device 
	 * 
	 */
	public void init(int workerId, Properties props) {
		log.debug(">init");
		String signaturealgoritm = props.getProperty(WorkerConfig.SIGNERPROPERTY_SIGNATUREALGORITHM);
		props = fixUpProperties(props);
		try { 
			((PKCS11CAToken)catoken).init(props, null, signaturealgoritm, workerId);	
		} catch(Exception e) {
			log.error("Error initializing PKCS11CryptoToken : " + e.getMessage(),e);
		}
		String authCode = props.getProperty("pin");
		if (authCode != null) {
			try { 
				this.activate(authCode);
			} catch(Exception e) {
				log.error("Error auto activating PKCS11CryptoToken : " + e.getMessage(),e);
			}
		}
		log.debug("<init");
	}

}
