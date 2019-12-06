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
package org.signserver.testutils;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class ExitException extends SecurityException {

    private static final long serialVersionUID = -4443566376708240848L;

    public final int number;

    /**
     * @param message
     */
    ExitException(int nr) {
        super("System exit with status " + nr);
        number = nr;
    }
}
