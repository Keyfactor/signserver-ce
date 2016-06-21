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
 * Implementation of Loggable taking a Throwable and evaluating getMessage()
 * when the log message is requested.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ExceptionLoggable implements Loggable {
    final private Throwable ex;
    
    /**
     * Create an instance given the supplied Throwable.
     * 
     * @param ex 
     */
    public ExceptionLoggable(final Throwable ex) {
        this.ex = ex;
    }
    
    /**
     * Log the message of the stored Throwable instance.
     * 
     * @return The log message
     */
    @Override
    public String toString() {
        return ex.getMessage();
    }
}
