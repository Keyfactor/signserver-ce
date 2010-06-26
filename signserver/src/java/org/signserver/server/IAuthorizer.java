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

import javax.persistence.EntityManager;

import org.signserver.common.ProcessRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;

/**
 * Interface that all authorization devices should implement regulating
 * access to a worker in the system
 * 
 * Its main method is: isAuthorized which have the responsibility of looking up if the
 *  client have access or not.
 * 
 * @author Philip Vendil 23 nov 2007
 *
 * @version $Id$
 */
public interface IAuthorizer {

    /** Log entry for username (if supported) for the authorized user. */
    String LOG_USERNAME = "AUTHORIZED_USERNAME";

    /** Log entry for authorized remote address. */
    String LOG_REMOTEADDRESS = "AUTHORIZED_ADDRESS";

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
	 * @param requestContext containing the optional clientCert client certificate or remote IP of the user, may also contain customly defined data.
	 * @throws SignServerException if unexpected error occurred during authorization.
	 * @throws IllegalRequestException if the requester isn't authorized or couldn't be authenticated for some other reason.
	 */
	void isAuthorized(ProcessRequest request, RequestContext requestContext) throws IllegalRequestException, SignServerException;
}
