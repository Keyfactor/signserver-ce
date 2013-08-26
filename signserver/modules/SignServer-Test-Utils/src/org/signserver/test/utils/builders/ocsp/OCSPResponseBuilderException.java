/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.signserver.test.utils.builders.ocsp;

/**
 * Exception indicating an error when creating an OCSP response.
 *
 *
 * @version $Id$
 */
public class OCSPResponseBuilderException extends Exception {

    private static final long serialVersionUID = -4430728688037371849L;

    public OCSPResponseBuilderException(Throwable cause) {
        super(cause);
    }

    public OCSPResponseBuilderException(String message, Throwable cause) {
        super(message, cause);
    }

    public OCSPResponseBuilderException(String message) {
        super(message);
    }
    
}
