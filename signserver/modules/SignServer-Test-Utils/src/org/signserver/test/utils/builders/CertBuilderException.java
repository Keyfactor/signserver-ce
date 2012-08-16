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
package org.signserver.test.utils.builders;

/**
 * Exception indicating a problem with creation of the certificate.
 *
 *
 * @version $Id: CertBuilderException.java 15189 2012-08-03 10:05:26Z netmackan $
 */
public class CertBuilderException extends Exception {

    public CertBuilderException(String msg) {
        super(msg);
    }

    public CertBuilderException(Throwable cause) {
        super(cause);
    }

    public CertBuilderException(String message, Throwable cause) {
        super(message, cause);
    }
    
}
