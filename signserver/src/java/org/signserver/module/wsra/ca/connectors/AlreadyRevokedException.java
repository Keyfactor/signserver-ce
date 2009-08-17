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
 
package org.signserver.module.wsra.ca.connectors;

/**
 * Exception thrown when trying to revoke a certificate
 * that already is revoked.
 * 
 * 
 * @author Philip Vendil 28 okt 2008
 *
 * @version $Id$
 */

public class AlreadyRevokedException extends Exception{

	public AlreadyRevokedException(String message) {
		super(message);
	}

	private static final long serialVersionUID = 1L;

}
