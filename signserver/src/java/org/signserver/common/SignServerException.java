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
 * @version $Id$
 */
public class SignServerException extends Exception {

	private static final long serialVersionUID = 1L;

	public SignServerException(String message) {
		super(message);
	}
	
	public SignServerException(String message, Throwable e) {
		super(message,e);
	}
	
	public String getMessage() {
		return super.getMessage();		
	}
	

}
