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
 * Exception thrown to indicate that a request or operation failed. This 
 * exception (or sub classes of it) is typically thrown when something failed 
 * on the server side.
 * 
 * If it is clear that the failure was caused by data supplied by the client, 
 * instead a IllegalRequestException may be thrown.
 * 
 * 
 * @author Philip Vendil
 * @author Markus Kilås
 * @see IllegalRequestException
 * @version $Id$
 */
public class SignServerException extends Exception {

    private static final long serialVersionUID = 1L;

    public SignServerException(String message) {
        super(message);
    }

    public SignServerException(String message, Throwable e) {
        super(message, e);
    }

    @Override
    public String getMessage() {
        return super.getMessage();
    }
}
