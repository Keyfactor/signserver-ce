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
 
import java.security.cert.X509Certificate;

import org.signserver.common.IProcessRequest;
import org.signserver.common.IProcessResponse;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignTokenAuthenticationFailureException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.server.IWorker;


/**
 * ISigner is an interface that all signers should implement
 * 
 * There exists a BaseService that can be extended covering some of it's functions
 * 
 * 
 * @author Philip Vendil
 * $Id: ISigner.java,v 1.3 2007-11-09 15:47:14 herrvendil Exp $
 */
public interface ISigner extends IWorker{

	public static final int AUTHTYPE_CLIENTCERT = 0;
	public static final int AUTHTYPE_NOAUTH     = 1;
	

	/**
    * Main method that does the actual signing according to the data in the request. 
    */
	public IProcessResponse signData(IProcessRequest signRequest,
	                              X509Certificate clientCert) throws IllegalRequestException, SignTokenOfflineException;
	

	
	/**
	 * Method used to activate a signer using the supplied authentication Code
	 * @param authenticationCode 
	 * @pram props, the configuration that should be used for activation, doesn't have to be the active one for smooth shift of keys.
	 */
	public void activateSigner(String authenticationCode) throws SignTokenAuthenticationFailureException, SignTokenOfflineException;
	
	/**
	 * Method used to deactivate a signer when it's not used anymort
	 */	
	public boolean deactivateSigner() throws SignTokenOfflineException;
	
	
	/**
	 * Method used to tell the signer to create a certificate request using its sign token.
	 */
	public ISignerCertReqData genCertificateRequest(ISignerCertReqInfo info) throws SignTokenOfflineException;
	
	/**
	 * Method specifying which typw of authentication that shuld be performed before signature is performed
	 * Returns one of the AUTHTYPE_ constants
	 */
	public int getAuthenticationType();
	
	/**
	 * Method used to remove a key in the signer that shouldn't be used any more
	 * @param purpose on of ISignToken.PURPOSE_ constants
	 * @return true if removal was successful.
	 */
	public boolean destroyKey(int purpose);
	
	
	
}
