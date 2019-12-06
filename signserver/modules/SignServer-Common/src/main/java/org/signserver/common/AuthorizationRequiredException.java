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
 * Exception thrown if the worker requires authorization.
 * 
 * @version $Id$
 */
public class AuthorizationRequiredException extends SignServerException {

    private static final long serialVersionUID = 1L;

    public AuthorizationRequiredException(String message) {
        super(message);
    }

    public AuthorizationRequiredException(String message, Throwable e) {
        super(message, e);
    }
}
