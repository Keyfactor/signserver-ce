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

package org.signserver.cli;

/**
 * Exception throws when an error occurs in an Admin Command (IadminCommand)
 *
 * @version $Id$
 */
public class ErrorAdminCommandException extends Exception{

	private static final long serialVersionUID = 1L;

	/**
     * Creates a new instance of ErrorAdminCommandException
     *
     * @param message error message
     */
    public ErrorAdminCommandException(String message) {
        super(message);
    }

    /**
     * Creates a new instance of ErrorAdminCommandException
     *
     * @param exception root cause of error
     */
    public ErrorAdminCommandException(Exception exception) {
        super(exception);
    }
}
