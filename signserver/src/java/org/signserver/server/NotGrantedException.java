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

import org.signserver.common.SignServerException;

/**
 * Exception thrown when a purchase of a request/response was not granted
 * by the accounter.
 * 
 * @author markus
 */
public class NotGrantedException extends SignServerException {

    public NotGrantedException(String message, Throwable e) {
        super(message, e);
    }

    public NotGrantedException(String message) {
        super(message);
    }

}
