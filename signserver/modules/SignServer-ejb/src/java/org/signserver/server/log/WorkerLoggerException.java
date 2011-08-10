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
package org.signserver.server.log;

/**
 * Exception thrown in case there was a problem writing out the log line.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class WorkerLoggerException extends Exception {

    public WorkerLoggerException(Throwable cause) {
        super(cause);
    }

    public WorkerLoggerException(String message, Throwable cause) {
        super(message, cause);
    }

    public WorkerLoggerException(String message) {
        super(message);
    }

}
