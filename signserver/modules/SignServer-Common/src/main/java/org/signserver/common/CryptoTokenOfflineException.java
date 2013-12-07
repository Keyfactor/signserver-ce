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
 * Exception thrown if a singing operation is performed but
 * the signing token isn't active. 
 * 
 * @author Philip Vendil
 * @version $Id$
 */
@WebFault
public class CryptoTokenOfflineException extends Exception {

    private static final long serialVersionUID = 1L;

    public CryptoTokenOfflineException(String message) {
        super(message);
    }

    public CryptoTokenOfflineException(Exception cause) {
        super(cause);
    }
}
