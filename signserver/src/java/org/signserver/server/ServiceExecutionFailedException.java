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
 
/**
 * IService is an interface that all services should implement
 * 
 * There exists a BaseService that can be extended covering some of it's functions
 * 
 * 
 * @author Philip Vendil
 * $Id: ServiceExecutionFailedException.java,v 1.1 2007-02-27 16:18:12 herrvendil Exp $
 */
public class ServiceExecutionFailedException extends Exception {


	private static final long serialVersionUID = 1L;

	public ServiceExecutionFailedException(String message, Throwable cause) {
		super(message, cause);		
	}

	public ServiceExecutionFailedException(String message) {
		super(message);
	}

}
