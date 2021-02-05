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
package org.signserver.server.archive;

/**
 * Exception thrown in case of exception initializing the archiver.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ArchiverInitException extends Exception {

    public ArchiverInitException(final String msg) {
        super(msg);
    }

    public ArchiverInitException(final Throwable cause) {
        super(cause);
    }

    public ArchiverInitException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
