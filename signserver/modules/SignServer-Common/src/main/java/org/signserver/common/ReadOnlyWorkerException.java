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
 * Exception thrown to indicate that the client is trying to modify or delete a worker that is read-only.
 *
 * @version $Id$
 */
public class ReadOnlyWorkerException extends Exception {

    public ReadOnlyWorkerException(String message) {
        super(message);
    }

}
