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
 * Exception thrown to indicate that the request sent by the client was not 
 * performed successfully.
 * 
 * Examples are missing arguments, invalid arguments, syntactically or 
 * semantically incorrect data supplied.
 * 
 * This exception should not be thrown by a worker if there is server-side 
 * exception unlikely to be caused by the client request. If the error is 
 * because of bad configuration or errors not related to the client instead a 
 * SignServerException should be used.
 * 
 * @author Philip Vendil
 * @author Markus Kilås
 * @see SignServerException
 * @version $Id$
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
}
