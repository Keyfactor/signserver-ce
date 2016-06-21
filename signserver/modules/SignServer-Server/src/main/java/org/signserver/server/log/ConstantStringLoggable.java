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
 * Implementation of Loggable taking a string value to be stored for later
 * logging.
 * This can be used when the logging message is already available at process
 * time in the worker, such as when logging string constants, when there will be
 * no extra processing needed to format the log message.
 * This avoids having to declare an anonymous inner class implementing the
 * interface in this case.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ConstantStringLoggable implements Loggable {
    private final String message;
    
    /**
     * Creates an instance using the supplied string value to be logged.
     * 
     * @param message Message to log
     */
    public ConstantStringLoggable(final String message) {
        this.message = message;
    }
    
    @Override
    public String toString() {
        return message;
    }
}
