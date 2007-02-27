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
 
package org.signserver.server.service;

import org.apache.log4j.Logger;
import org.signserver.server.ServiceExecutionFailedException;

/**
 * Dummy Service that is used for testing and demonstration purposes.
 * Only output to the log that it have been called
 * 
 * 
 * @author Philip Vendil 2007 jan 23
 *
 * @version $Id: DummyService.java,v 1.1 2007-02-27 16:18:28 herrvendil Exp $
 */

public class DummyService extends BaseService {

	public transient Logger log = Logger.getLogger(this.getClass());
	/**
	 * Example of super simple service.
	 * 
	 * @see org.signserver.server.service.IService#work()
	 */
	public void work() throws ServiceExecutionFailedException {
		log.info("DummyService.work() called.");
	}

}
