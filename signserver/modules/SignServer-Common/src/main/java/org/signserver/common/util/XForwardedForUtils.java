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
package org.signserver.common.util;

import org.apache.log4j.Logger;
import org.signserver.common.RequestContext;

/**
 * Utility methods for archiving
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class XForwardedForUtils {

    private static Logger LOG = Logger.getLogger(XForwardedForUtils.class);
    
    /**
     * Utility method to extract the forwarded IP address from
     * the X-Forwarded-For header (if present).
     * The last IP address in the comma-separated list will be returned.
     * 
     * @param requestContext Request context
     * @return The last IP address in the list given by the X-Forwarded-For header
     *         or null if the header is missing from the request
     */
    public static String getXForwardedForIP(final RequestContext requestContext) {
        final String[] ips = getXForwardedForIPs(requestContext, 1);
        
        if (ips == null) {
            return null;
        } else if (ips.length == 0) {
            return null;
        } else {
            return ips[0];
        }
    }
    
    /**
     * Utility method to extract forwarded IP addresses from
     * the X-Forwarded-For header (if present).
     * The given number of IP address from the end of the comma-separated list will be returned, or all if the list is shorter.
     * 
     * @param requestContext
     * @param maxAddresses Maximum number of IP addresses to return
     * @return An array with the IP addresses from the end of X-ForwardedFor header, at most maxAddresses elements, or null if the header is missing.
     *          If the header is the empty string, a zero-length array is returned.
     */
    public static String[] getXForwardedForIPs(final RequestContext requestContext, final int maxAddresses) {
        final String xForwardedFor = (String) requestContext.get(RequestContext.X_FORWARDED_FOR);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Using X-Forwarded-For: " + xForwardedFor);
        }
        
        if (xForwardedFor != null) {
            final String ipsString = xForwardedFor.trim();
            
            if (ipsString.length() == 0) {
                return new String[0];
            }
            
            final String[] ips = ipsString.split(",");
            final String[] result = new String[Math.min(maxAddresses, ips.length)];
            
            for (int i = 0; i < result.length; i++) {
                result[i] = ips[ips.length - i - 1].trim();
            }
            
            return result;
        }
       
        return null;
    }
    
}
