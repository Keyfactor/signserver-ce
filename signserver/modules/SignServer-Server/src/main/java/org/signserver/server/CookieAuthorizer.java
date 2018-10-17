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

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.server.log.LogMap;
import org.signserver.common.RequestContext;

 /** 
  * Cookie Authorizer is used for Airlock feature where custom client cookies
  * are added to RequestContext, parsed, analyzed and then logged
  * based on customer requirements/preferences.
  * 
  * This feature could be used to profile/black list IP ranges, user OS, etc.
  * one can e.g. add "strange" IP ranges to Apache Web server .htacess 
  * and deny them access to SignServer functionality!
  * 
  * @author netmakan
  * @author georgem
           
 * @version $Id$
 */
public class CookieAuthorizer implements IAuthorizer {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(CookieAuthorizer.class);

    // Worker properties
    //...

    // Log fields
    //...

    // Default values
    //...

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    //...

    @Override
    public void init(int workerId, WorkerConfig config, EntityManager em)
            throws SignServerException {
        // Read properties
        //...
    }

    @Override
    public void isAuthorized(Request request,
            RequestContext requestContext) throws IllegalRequestException,
            SignServerException {
        final Object o = requestContext.get(RequestContext.CLIENT_CREDENTIAL_CERTIFICATE); // or CLIENT_CREDENTIAL_PASSWORD

        final LogMap logMap = LogMap.getInstance(requestContext);
        
        //Parse/analyze the cookies from RequestContext then add SOME of them to LogMap
        Map<String, String>  cookiesMap = (HashMap) requestContext.get(RequestContext.REQUEST_COOKIES);
        //Cookie[] cookies = new Cookie(cookiesMap.keySet(), cookiesMap.values());
        for ( int i = 0; i< cookiesMap.size(); i++ ) {
            System.out.println("\n SwissSign Cookie["+ i+ "] " + cookiesMap.keySet().toArray()[i] + ":" + cookiesMap.values().toArray()[i]);
        }
        
        logMap.putAll(cookiesMap);
    }

    @Override
    public List<String> getFatalErrors() {
        return configErrors;
    }

}
