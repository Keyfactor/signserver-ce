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
package org.signserver.server;

/**
 * Exception indicating a problem for the Accounter implementation to properly
 * perform the purchase.
 * 
 * Example usage are to indicate a problem connecting to the accounting 
 * database/system.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AccounterException extends Exception {

    public AccounterException(Throwable cause) {
        super(cause);
    }

    public AccounterException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccounterException(String message) {
        super(message);
    }

}
