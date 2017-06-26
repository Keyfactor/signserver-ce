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
 * Exception thrown to indicate that a service is unavailable and the request
 * could not be fulfilled. This exception (or sub classes of it) 
 * is typically thrown when something failed 
 * on the server side.
 * 
 * If it is clear that the failure was caused by data supplied by the client, 
 * instead a IllegalRequestException may be thrown. 
 *
 * @author Marcus Lundblad
 * @see IllegalRequestException
 * @version $Id$
 */
public class ServiceUnavailableException extends SignServerException {

    private static final long serialVersionUID = 1L;

    public ServiceUnavailableException(String message) {
        super(message);
    }

    public ServiceUnavailableException(String message, Throwable e) {
        super(message, e);
    }
}
