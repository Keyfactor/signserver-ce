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
 
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.IProcessRequest;
import org.signserver.common.IProcessResponse;
import org.signserver.common.ISignerCertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.server.IWorker;
import org.signserver.server.RequestContext;


/**
 * ISigner is an interface that all signers should implement
 * 
 * There exists a BaseService that can be extended covering some of it's functions
 * 
 * 
 * @author Philip Vendil
 * $Id: ISigner.java,v 1.5 2007-12-02 20:35:18 herrvendil Exp $
 */
public interface ISigner extends IWorker{

	public static final String AUTHTYPE_CLIENTCERT = "CLIENTCERT";
	public static final String AUTHTYPE_NOAUTH     = "NOAUTH";
	

	/**
    * Main method that does the actual signing according to the data in the request.
    * 
    *  @throws IllegalRequestException if requests contain unsupported data.
    *  @throws CryptoTokenOfflineException if the token performing cryptographic operations is off-line.
    *  @throws SignServerException if general failure occurred during the operation.
    */
	public IProcessResponse processData(IProcessRequest signRequest,
	                              RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;
	

	
	/**
	 * Method used to activate a signer using the supplied authentication Code
	 * @param authenticationCode 
	 * @param props the configuration that should be used for activation, doesn't have to be the active one for smooth shift of keys.
	 */
	public void activateSigner(String authenticationCode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException;
	
	/**
	 * Method used to deactivate a signer when it's not used anymort
	 */	
	public boolean deactivateSigner() throws CryptoTokenOfflineException;
	
	
	/**
	 * Method used to tell the signer to create a certificate request using its sign token.
	 */
	public ISignerCertReqData genCertificateRequest(ISignerCertReqInfo info) throws CryptoTokenOfflineException;
	
	/**
	 * Method specifying which type of authentication that should be performed before signature is performed
	 * Returns one of the AUTHTYPE_ constants
	 */
	public String getAuthenticationType();
	
	/**
	 * Method used to remove a key in the signer that shouldn't be used any more
	 * @param purpose on of ICryptoToken.PURPOSE_ constants
	 * @return true if removal was successful.
	 */
	public boolean destroyKey(int purpose);
	
	
	
}
