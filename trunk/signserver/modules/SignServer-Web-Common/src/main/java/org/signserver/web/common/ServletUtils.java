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
package org.signserver.web.common;

import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Logger;

/**
 * Utility functions used by the servlet implementations.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ServletUtils {
    /* Logger for this class */
    private static Logger LOG = Logger.getLogger(ServletUtils.class);

    /**
     * Property used to indicate an overriding worker name property in
     * a forwarded servlet request (used by the worker-specifyable servlets).
     */
    public static final String WORKERNAME_PROPERTY_OVERRIDE = "workerNameOverride";

    /**
     * Parse out the worker name from a servlet request.
     * 
     * @param req Servlet request
     * @param uriPrefix The prefix of the request URI (such as /process/worker/)
     * @return A worker name if matching, otherwise null
     */
    public static String parseWorkerName(final HttpServletRequest req,
                           final String uriPrefix) {
        final String requestURI = req.getRequestURI();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Parsing request: " + requestURI);
        }

        if (requestURI.length() >= uriPrefix.length() &&
            uriPrefix.equals(requestURI.substring(0, uriPrefix.length()))) {
            final String namePart = requestURI.substring(uriPrefix.length());

            // if the parts after /worker/ starts with another / then just reject the URL
            if (namePart.length() > 0 && namePart.charAt(0) == '/') {
                    return null;
            }

            return namePart;
        }

        return null;
    }
}
