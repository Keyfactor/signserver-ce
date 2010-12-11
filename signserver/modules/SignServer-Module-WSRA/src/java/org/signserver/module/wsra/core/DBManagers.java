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
 
package org.signserver.module.wsra.core;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.module.wsra.common.WSRAConstants;
import org.signserver.server.cryptotokens.ICryptoToken;

/**
 * Class in charge of all database managers.
 * 
 * All managers can be accessed using
 * public field access.
 * 
 * 
 * @author Philip Vendil 25 okt 2008
 *
 * @version $Id$
 */

public class DBManagers {
	
	private static final Logger log = Logger.getLogger(DBManagers.class);
	
	public final OrganizationManager om;
	public final ProductManager pm;
	public final TokenManager tm;
	public final TransactionManager trm;
	public final UserManager um;
	public final DataBankManager dbm;
	
	final EntityManager workerEntityManager;
	
	public DBManagers(WorkerConfig wc, 
			          EntityManager workerEntityManager,
			          Set<Class<?>> availableTokenProfileClasses,
			          Set<Class<?>> availableAuthTypeClasses,
			          ICryptoToken ct,
			          Certificate workerCertificate,
			          String nodeId) throws SignServerException{    	
    		try{    			
    			boolean encryptSensitiveData = wc.getProperty(WSRAConstants.SETTING_ENCRYPTTOKENDATA, "FALSE").equalsIgnoreCase("TRUE");
 	
    			if(encryptSensitiveData){
    				tm = new TokenManager(workerEntityManager,availableTokenProfileClasses,
    						encryptSensitiveData,(X509Certificate) workerCertificate,
    						ct.getPrivateKey(ICryptoToken.PURPOSE_DECRYPT),
    						ct.getProvider(ICryptoToken.PURPOSE_DECRYPT));	

    			}else{
    				tm = new TokenManager(workerEntityManager,availableTokenProfileClasses);
    			}

    			um = new UserManager(workerEntityManager,availableAuthTypeClasses,tm);
    			pm = new ProductManager(workerEntityManager);   
    			om = new OrganizationManager(workerEntityManager,um,pm);    			 	
    			trm = new TransactionManager(workerEntityManager,nodeId);
    			dbm = new DataBankManager(workerEntityManager);
    			this.workerEntityManager = workerEntityManager;
    		}catch(CryptoTokenOfflineException e){
    			log.error("Error when initializing TokenManager, cryptotoken offline",e);
    			throw new SignServerException("Error, CryptoToken offline : " + e.getMessage());
    		}    	
	}

}
