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
package org.signserver.server;

import java.util.LinkedList;
import java.util.List;

/**
 * Utility methods for Exception handling.
 *
 * @author Markus Kilås
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ExceptionUtil {
  
    /**
     * Compile a list of all (unique) messages in the exception's caused by
     * list.
     * @param exception The obtain all exception messages from
     * @return List of exception messages
     */
    public static final List<String> getCauseMessages(Throwable exception) {
        // collect cause messages
        final List<String> causes = new LinkedList<>();

        causes.add(exception.getMessage());

        Throwable cause = exception.getCause();

        // iterate throug cause until we reach the bottom
        while (cause != null) {
            final String causeMessage = cause.getMessage();

            // if cause message wasn't already seen, add it to the list
            if (causeMessage != null && !causes.contains(causeMessage)) {
                causes.add(causeMessage);
            }

            cause = cause.getCause();
        }

        return causes;
    }
}
