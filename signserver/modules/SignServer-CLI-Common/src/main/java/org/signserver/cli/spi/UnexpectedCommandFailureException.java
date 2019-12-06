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
 * Exception thrown in case an unexpected failure happened when executing a 
 * CLI command. 
 * 
 * Typically this exception will cause the CLI to display a 
 * stacktrace. Commands should try to use the CommandFailureException with a 
 * good error message as far as possible and only use this for unexpected 
 * failures.
 * @author Markus Kilås
 * @version $Id$
 * @see CommandFailureException
 */
public class UnexpectedCommandFailureException extends Exception {

    public UnexpectedCommandFailureException(Throwable cause) {
        super(cause);
    }

    public UnexpectedCommandFailureException(String message, Throwable cause) {
        super(message, cause);
    }

}
