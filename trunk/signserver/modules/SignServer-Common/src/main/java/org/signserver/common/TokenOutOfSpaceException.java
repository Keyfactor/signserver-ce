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
 * Exception indicating that the token can not, or is not allowed to, create
 * more entries.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class TokenOutOfSpaceException extends CryptoTokenOfflineException {

    public TokenOutOfSpaceException(String message) {
        super(message);
    }

    public TokenOutOfSpaceException(Exception cause) {
        super(cause);
    }

    public TokenOutOfSpaceException(String message, Throwable cause) {
        super(message, cause);
    }

}
