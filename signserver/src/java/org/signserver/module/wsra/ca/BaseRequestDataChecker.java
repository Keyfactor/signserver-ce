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
 
package org.signserver.module.wsra.ca;

import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.module.wsra.core.DBManagers;

/**
 * 
 * Base class taking care of the basic initialization.
 * 
 * @author Philip Vendil 25 okt 2008
 *
 * @version $Id$
 */

public abstract class BaseRequestDataChecker implements IRequestDataChecker {

	protected WorkerConfig ws;
	protected DBManagers db;
	
	/**
	 * @see org.signserver.module.wsra.ca.IRequestDataChecker#init(org.signserver.common.WorkerConfig, org.signserver.module.wsra.core.DBManagers)
	 */
	public void init(WorkerConfig ws, DBManagers db) throws SignServerException {
		this.ws = ws;
		this.db = db;
	}

}
