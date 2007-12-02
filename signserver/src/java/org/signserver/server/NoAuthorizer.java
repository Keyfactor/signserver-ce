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

import org.signserver.common.IProcessRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;

/**
 * Simple IAuthorizer accepting all requests.
 * 
 * 
 * @author Philip Vendil 24 nov 2007
 *
 * @version $Id: NoAuthorizer.java,v 1.2 2007-12-02 20:35:18 herrvendil Exp $
 */

public class NoAuthorizer implements IAuthorizer {

	/**
	 * @see org.signserver.server.IAuthorizer#init(int, org.signserver.common.WorkerConfig, javax.persistence.EntityManager)
	 */
	public void init(int workerId, WorkerConfig config, EntityManager em)
			throws SignServerException {

	}

	/**
	 * @see org.signserver.server.IAuthorizer#isAuthorized(IProcessRequest, RequestContext)
	 */
	public void isAuthorized(IProcessRequest request,RequestContext requestContext)
			throws SignServerException, IllegalRequestException {
	}

}
