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
 * Exception indicating that the supplied alias did not exist in the token.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class NoSuchAliasException extends Exception {

    public NoSuchAliasException(String message) {
        super(message);
    }

    public NoSuchAliasException(String message, Throwable cause) {
        super(message, cause);
    }

    public NoSuchAliasException(Throwable cause) {
        super(cause);
    }

}
