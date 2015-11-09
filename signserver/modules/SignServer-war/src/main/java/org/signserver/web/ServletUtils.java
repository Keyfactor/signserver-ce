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
package org.signserver.web;

import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Logger;

/**
 * Utility functions used by the servlet implementations.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
class ServletUtils {
    /* Logger for this class */
    private static Logger LOG = Logger.getLogger(ServletUtils.class);

    static String parseWorkerName(final HttpServletRequest req,
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
