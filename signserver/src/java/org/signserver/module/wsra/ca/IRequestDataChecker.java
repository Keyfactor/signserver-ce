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

import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.module.wsra.beans.UserDataBean;
import org.signserver.module.wsra.core.DBManagers;

/**
 * Class that goes through the requested data
 * and makes sure it contains valid data.
 * <p>
 * Main method is checkRequestData()
 * 
 * 
 * @author Philip Vendil 25 okt 2008
 *
 * @version $Id$
 */

public interface IRequestDataChecker {
	
	/**
	 * Initializes the request data checker, must be
	 * called after instantiation.
	 * 
	 * @param ws the current worker configuration
	 * @param db the database manager
	 * @throws SignServerException internal server error.
	 */
	void init(WorkerConfig ws,DBManagers db) throws SignServerException
	;
	
	/**
	 * Method that goes through the requested data
	 * and makes sure it contains valid data. 
	 * 
	 * If the data isn't valid the method can perform
	 * one of two actions, either it can silently correct 
	 * and return it or it can throw IllegalRequestException
	 * with a message of the illegal data.
	 * 
	 * @param caller the user performing the WS call.
	 * @param requestData the actual request data.
	 * @param importData imported data from a trusted source. This
	 * parameter may be null if no data import have been done.
	 * @return the processed request data
	 * @throws IllegalRequestException if the request contained 
	 * in valid data.
	 * @throws SignServerException internal server error.
	 */
	ICertRequestData checkRequestData(UserDataBean caller, ICertRequestData requestData, ICertRequestData importedData) throws IllegalRequestException, SignServerException;
	
	

}
