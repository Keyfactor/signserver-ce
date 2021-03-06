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
package org.signserver.common.signedrequest;

/**
 * Exception for errors occuring when signing a signing request.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class SignedRequestException extends Exception {

    public SignedRequestException(String message) {
        super(message);
    }

    public SignedRequestException(String message, Throwable cause) {
        super(message, cause);
    }

    public SignedRequestException(Throwable cause) {
        super(cause);
    }
    
}
