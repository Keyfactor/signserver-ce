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
public class CommandFailureException extends Exception {

    private Integer exitCode;

    /**
     * Constructs an instance of <code>CommandFailureException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CommandFailureException(String msg) {
        super(msg);
    }

    public CommandFailureException(String msg, Integer exitCode) {
        super(msg);
        this.exitCode = exitCode;
    }

    public Integer getExitCode() {
        return exitCode;
    }
    
}
