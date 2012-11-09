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

import java.util.HashMap;
import org.signserver.common.RequestContext;

/**
 * Map holding the log entries used by the Worker logger for a request.
 * 
 * Workers (and other components) should use this method to get the log map 
 * for the current transaction to put in log entries into.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class LogMap extends HashMap<String, String> {
  
    /**
     * Get the LogMap from the RequestContext or create and put a new one
     * if it does not exist yet.
     * @param requestContext The request context for the transaction
     * @return An LogMap instance now existing in the RequestContext
     */
    public static LogMap getInstance(final RequestContext requestContext) {
        final LogMap result;
        final Object o = requestContext.get(RequestContext.LOGMAP);
        if (o instanceof LogMap) {
            result = (LogMap) o;
        } else {
            result = new LogMap();
            requestContext.put(RequestContext.LOGMAP, result);
        }
        return result;
    }
}
