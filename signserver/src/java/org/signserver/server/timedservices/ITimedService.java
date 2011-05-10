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

package org.signserver.server.timedservices;

import org.signserver.server.IWorker;
import org.signserver.server.ServiceExecutionFailedException;


/**
 * ITimedService is an interface that all services should implement
 * 
 * There exists a BaseTimedService that can be extended covering some of it's functions
 * 
 * 
 * @author Philip Vendil
 * $Id$
 */
public interface ITimedService extends IWorker{
	 
	/**
	 * Constant indicating if the service should stop executing
	 */
	public static final long DONT_EXECUTE = -1;
	
	
	
	/**
	 * Method that should do the actual work and should
	 * be implemented by all services. The method is run
	 * at a periodical interval defined in getNextInterval.
	 * 
	 * @throws ServiceExecutionFailedException if execution of a service failed
	 */
	public void work() throws ServiceExecutionFailedException;
	
	/**
	 * @return should return the milliseconds to next time the service should
	 * execute, or -1 (DONE_EXECUTE) if the service should stop executing.
	 * 
	 * IMPORTANT, this have changed since 2.0 version were seconds were 
	 * specified. This shouldn't be confused with the INTERVAL setting 
	 * that is still configured in seconds.
	 */
	public long getNextInterval();
	
	/**
	 * @return true if the service should be active and run
	 */
	public boolean isActive();
	
	/**
	 * @return true if it should be a singleton only run at one node at
	 * the time, of false if it should be run on all nodes simultaneously.
	 */
	public boolean isSingleton();

}
