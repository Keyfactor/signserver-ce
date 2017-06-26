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

import javax.xml.ws.WebFault;

/**
 * Exception thrown when a runtime implementation doesn't support a given operation.
 * F.ex. used when trying to import signing certificates to a crypto token
 * not supporting this, like a soft crypto token.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
@WebFault
public class OperationUnsupportedException extends Exception {
    private static final long serialVersionUID = 1L;

    public OperationUnsupportedException(final String message) {
        super(message);
    }

    public OperationUnsupportedException(String message, Throwable cause) {
        super(message, cause);
    }

    public OperationUnsupportedException(Throwable cause) {
        super(cause);
    }

}
