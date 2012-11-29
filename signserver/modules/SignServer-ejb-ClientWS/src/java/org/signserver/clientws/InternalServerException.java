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
package org.signserver.clientws;

/**
 * Representation of a failure at the server side.
 * 
 * In case the request could not be processed by some error at the server side 
 * such as miss-configuration or service unavailability.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class InternalServerException extends Exception {

    /**
     * Creates a new instance of
     * <code>InternalServerException</code> without detail message.
     */
    public InternalServerException() {
    }

    /**
     * Constructs an instance of
     * <code>InternalServerException</code> with the specified detail message.
     *
     * @param msg the detail message.
     */
    public InternalServerException(String msg) {
        super(msg);
    }
}
