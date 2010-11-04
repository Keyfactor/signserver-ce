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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.model.ca.catoken.ICAToken;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.WorkerConfig;


/**
 * Class used to connect to the PrimeCard HSM card.
 * 
 * @see org.signserver.server.cryptotokens.ICryptoToken
 * @author Philip Vendil
 * @version $Id$
 */

public class PrimeCardHSMCryptoToken extends CryptoTokenBase implements ICryptoToken {

	private static final Logger log = Logger.getLogger(PrimeCardHSMCryptoToken.class);

	private static final String PrimeCATokenClassPath = "se.primeKey.caToken.card.PrimeCAToken";
	
	public PrimeCardHSMCryptoToken(){
		  
		try {
			Class<?> implClass = Class.forName(PrimeCATokenClassPath);
			catoken = (ICAToken) implClass.newInstance();
		} catch (ClassNotFoundException e) {
			log.error("Error initializing PrimeCardHSM",e);
		}catch (InstantiationException e) {
			log.error("Error initializing PrimeCardHSM",e);
		} catch (IllegalAccessException e) {
			log.error("Error initializing PrimeCardHSM",e);
		}
		 
	}

	/**
	 * Method initializing the primecardHSM device 
	 * 
	 */
	public void init(int workerId, Properties props) {
		log.debug(">init");
		String signaturealgoritm = props.getProperty(WorkerConfig.SIGNERPROPERTY_SIGNATUREALGORITHM);
		props = fixUpProperties(props);
		try {
			((ICAToken)catoken).init(props, null, signaturealgoritm, workerId);
		} catch (Exception e1) {
			log.error("Error initializing PrimeCardHSM",e1);
		}	
		String authCode = props.getProperty("authCode");
		if(authCode != null){
			try{ 
				this.activate(authCode);
			}catch(Exception e){
				log.error("Error activating PrimeCardHSM CryptoToken", e);
			}
		}
		log.debug("<init");
	}

    public KeyStore getKeyStore() throws UnsupportedOperationException,
            CryptoTokenOfflineException, KeyStoreException {
        throw new UnsupportedOperationException(
                "Operation not supported by crypto token.");
    }
}
