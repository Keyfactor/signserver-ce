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
package org.signserver.adminws;

/**
 * Exception indicating that the user is not authorized to perform the
 * operation.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AdminNotAuthorizedException extends Exception {

    /** serialVersionUID for this class. */
    private static final long serialVersionUID = 1;

    public AdminNotAuthorizedException(String message, Throwable cause) {
        super(message, cause);
    }

    public AdminNotAuthorizedException(String message) {
        super(message);
    }

    public AdminNotAuthorizedException() {
    }
}
