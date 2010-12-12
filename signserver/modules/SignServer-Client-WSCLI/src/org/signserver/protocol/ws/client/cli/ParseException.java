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

package org.signserver.protocol.ws.client.cli;

/**
 * Exception thrown after a problem occured during
 * property file parsing. 
 * 
 * 
 * @author Philip Vendil 17 dec 2007
 *
 * @version $Id$
 */

public class ParseException extends Exception {

	private static final long serialVersionUID = 1L;

	public ParseException(String message) {
		super(message);
	}

	public ParseException(String message, Throwable throwable) {
		super(message, throwable);
	}

}
