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

import java.security.cert.X509Certificate;

import javax.persistence.EntityManager;

import org.signserver.common.IProcessRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;

/**
 * Interface that all  authorization devices should implement regulating
 * access to a worker in the system
 * 
 * Its main method is: isAuthorized which have the responsibility of looking up if the
 *  client have access or not.
 * 
 * @author Philip Vendil 23 nov 2007
 *
 * @version $Id: IAuthorizer.java,v 1.1 2007-11-27 06:05:04 herrvendil Exp $
 */
public interface IAuthorizer {
	
	/**
	 * Method called by the worker upon first call to the authenticator after instantiation.
	 * 
	 * @param workerId id of worker.
	 * @param config active worker configuration of worker
	 * @param em the SignServer EntityManager
	 * @throws SignServerException if unexpected error occurred during initialization.
	 */
	void init(int workerId, WorkerConfig config, EntityManager em) throws SignServerException;

	/**
	 * 
	 * Main method determining if the requester is authorized to process the data in the request.
	 * 
	 * @param request the request data sent to the worker to process.
	 * @param clientCert client certificate of the user, may be null if no client certificate authentication was used.
	 * @param clientIP IP of the requesting client, may be null.
	 * @throws SignServerException if unexpected error occurred during authorization.
	 * @throws IllegalRequestException if the requester isn't authorized or couldn't be authenticated for some other reason.
	 */
	void isAuthorized(IProcessRequest request, X509Certificate clientCert, String clientIP) throws IllegalRequestException, SignServerException;
}
