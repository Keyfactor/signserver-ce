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
package org.signserver.cli.spi;

/**
 *
 * @author Markus Kilås
 */
public class IllegalCommandArgumentsException extends Exception {

    /**
     * Creates a new instance of <code>IllegalAdminArgsException</code> without detail message.
     */
    public IllegalCommandArgumentsException() {
    }

    /**
     * Constructs an instance of <code>IllegalAdminArgsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public IllegalCommandArgumentsException(String msg) {
        super(msg);
    }
}
