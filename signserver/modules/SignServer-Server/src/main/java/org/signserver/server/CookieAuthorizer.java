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
import javax.persistence.EntityManager;
import javax.servlet.http.Cookie;
import org.apache.log4j.Logger;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.server.log.LogMap;
import org.signserver.common.RequestContext;
import org.apache.commons.lang.StringUtils;

 /** 
  * Cookie Authorizer is used for Airlock feature where custom client cookies
  * are added to RequestContext, parsed, analyzed and then logged
  * based on customer requirements/preferences.
  * 
  * This feature could be used to profile/black list IP ranges, user OS, etc.
  * one can e.g. add "strange" IP ranges to Apache Web server .htacess 
  * and deny them access to SignServer functionality!
  * 
  * @author netmackan
  * @author georgem
           
 * @version $Id$
 */
public class CookieAuthorizer implements IAuthorizer {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(CookieAuthorizer.class);
    
    /** default cookies prefix for Airlock feature */
    private static final String REQUEST_COOKIES_PREFIX = "REQUEST_COOKIES_PREFIX";
    
    /** default selection rule for cookies from client request to be logged */
    private static final String ALLOW_ANY = "ALLOW_ANY";

    // Worker propertifes
    //...

    // Log fields
    //...

    // Default values
    //...

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Cookies configuration properties
    private String cookiePrefix;
    
    @Override
    public void init(final int workerId, final WorkerConfig config, final EntityManager em)
            throws SignServerException {
        // Get COOKIES_PREFIX property from a Worker configuration
        cookiePrefix = config.getProperty(REQUEST_COOKIES_PREFIX);
        // Check if ALLOW_ANY cookie rule is set
        String allowAny = config.getProperty(ALLOW_ANY);
        
        // Check that COOKIES_PREFIX is set 
        if (StringUtils.trim(cookiePrefix) == null) {
            configErrors.add("Required property is not set "
                    + REQUEST_COOKIES_PREFIX);
        }
        //and ALLOW_ANY property must be set to TRUE in Worker 
        if (!Boolean.TRUE.toString().equalsIgnoreCase(allowAny)) {
            configErrors.add("Worker property "
                    + ALLOW_ANY + " must be set to TRUE");
        }
    }

    @Override
    public void isAuthorized(Request request,
            RequestContext requestContext) throws IllegalRequestException,
            SignServerException {
        final Object o = requestContext.get(RequestContext.CLIENT_CREDENTIAL_CERTIFICATE); // or CLIENT_CREDENTIAL_PASSWORD

        final LogMap logMap = LogMap.getInstance(requestContext);
        
        //Parse/analyze the cookies from RequestContext then add SOME of them to LogMap
        Cookie[] cookies = (Cookie[]) requestContext.get(RequestContext.REQUEST_COOKIES);
                
        if (cookies != null) {
            int i = 0;
            for (Cookie cookie : cookies) {
                StringBuilder cookiebuf = new StringBuilder();
                i++;
                //Log cookies with pre-configured prefix
                if (cookiePrefix != null && !cookie.getName().startsWith(cookiePrefix)) {
                    cookiebuf.append(cookiePrefix);
                }
                cookiebuf.append(cookie.getName());
                
                //Log cookies with correct prefix
                logMap.put(cookiebuf.toString(), CookieUtils.fromCookieValue(cookie.getValue()));
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Client Cookie[" + i + "]:" + cookie.getName()+ ":"+ cookie.getValue());
                }
            }
        }
    }

    @Override
    public List<String> getFatalErrors() {
        return configErrors;
    }

}
