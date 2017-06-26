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
 * Exception indicating that one or more of the supplied crypto token
 * parameters was unknown or unsupported by the crypto token implementation.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class UnsupportedCryptoTokenParameter extends Exception {

    public UnsupportedCryptoTokenParameter(String message) {
        super(message);
    }

    public UnsupportedCryptoTokenParameter(String message, Throwable cause) {
        super(message, cause);
    }

    public UnsupportedCryptoTokenParameter(Throwable cause) {
        super(cause);
    }

}
