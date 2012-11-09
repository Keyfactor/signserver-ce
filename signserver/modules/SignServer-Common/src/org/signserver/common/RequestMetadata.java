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

import java.util.HashMap;

/**
 * Map holding the request meta data for a request.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class RequestMetadata extends HashMap<String, String> {
  
    /**
     * Get the RequestMetadata from the RequestContext or create and put a new one
     * if it does not exist yet.
     * @param requestContext The request context for the transaction
     * @return An RequestMetadata instance now existing in the RequestContext
     */
    public static RequestMetadata getInstance(final RequestContext requestContext) {
        final RequestMetadata result;
        final Object o = requestContext.get(RequestContext.REQUEST_METADATA);
        if (o instanceof RequestMetadata) {
            result = (RequestMetadata) o;
        } else {
            result = new RequestMetadata();
            requestContext.put(RequestContext.REQUEST_METADATA, result);
        }
        return result;
    }
}
