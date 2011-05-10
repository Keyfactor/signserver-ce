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

package org.signserver.common.clusterclassloader;



/**
 * 
 * Exception thrown if PAR file was badly structured or
 * didn't have all required fields in the deployment
 * descriptor.
 * 
 * @author Philip Vendil 15 maj 2008
 *
 */

public class IllegalMARFileException extends Exception {

	private static final long serialVersionUID = 1L;

	public IllegalMARFileException(String message, Throwable cause) {
		super(message, cause);
	}

	public IllegalMARFileException(String message) {
		super(message);
	}

}
