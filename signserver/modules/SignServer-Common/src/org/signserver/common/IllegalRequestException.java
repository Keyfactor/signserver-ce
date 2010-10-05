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

 
package org.signserver.common;

/**
 * Exception thrown if a singing operation is performed but
 * the signing token isn't active. 
 * 
 * @author Philip Vendil
 * $id$
 */

public class IllegalRequestException extends Exception {

	private static final long serialVersionUID = 1L;

	public IllegalRequestException(String message) {
		super(message);
	}

        public IllegalRequestException(String message, Throwable cause) {
		super(message, cause);
	}

        public IllegalRequestException(Throwable cause) {
		super(cause);
	}
	
	public String getMessage() {
		return super.getMessage();
	}


}
