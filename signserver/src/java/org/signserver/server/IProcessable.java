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

package org.signserver.server;
 
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessResponse;
import org.signserver.common.ICertReqData;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.server.IWorker;


/**
 * IProcessable is an interface that all processable workers should implement
 * 
 * There exists a BaseTimedService that can be extended covering some of it's functions
 * 
 * 
 * @author Philip Vendil
 * $Id$
 */
public interface IProcessable extends IWorker{

	public static final String AUTHTYPE_CLIENTCERT = "CLIENTCERT";
	public static final String AUTHTYPE_NOAUTH     = "NOAUTH";
	
	

	/**
    * Main method that does the actual signing according to the data in the request.
    * 
    *  @throws IllegalRequestException if requests contain unsupported data.
    *  @throws CryptoTokenOfflineException if the token performing cryptographic operations is off-line.
    *  @throws SignServerException if general failure occurred during the operation.
    */
	public ProcessResponse processData(ProcessRequest signRequest,
	                              RequestContext requestContext) throws IllegalRequestException, CryptoTokenOfflineException, SignServerException;
	

	
	/**
	 * Method used to activate a processable worker using the supplied authentication Code
	 * 
	 * Optional method, if not supported throw a CryptoTokenOfflineException
	 * 
	 * @param authenticationCode 
	 * @param props the configuration that should be used for activation, doesn't have to be the active one for smooth shift of keys.
	 */
	public void activateSigner(String authenticationCode) throws CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException;
	
	/**
	 * Method used to deactivate a processable worker when it's not used anymore
	 * 
	 * Optional method, if not supported throw a CryptoTokenOfflineException
	 */	
	public boolean deactivateSigner() throws CryptoTokenOfflineException;
	
	
	/**
	 * Method used to tell the processable worker to create a certificate request using its crypto token.
	 * 
	 * Optional method, if not supported throw a CryptoTokenOfflineException
	 */
	public ICertReqData genCertificateRequest(ISignerCertReqInfo info) throws CryptoTokenOfflineException;
	
	/**
	 * Method specifying which type of authentication that should be performed before signature is performed
	 * Returns one of the AUTHTYPE_ constants
	 */
	public String getAuthenticationType();
	
	/**
	 * Method used to remove a key in the processable worker that shouldn't be used any more
	 * 
	 * Optional method, if not supported return false.
	 * 
	 * @param purpose on of ICryptoToken.PURPOSE_ constants
	 * @return true if removal was successful.
	 */
	public boolean destroyKey(int purpose);
	
	
	
}
