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
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.server.log.LogMap;

/**
 * Skeleton authorizer...
 * <p>
 * The authorizer has the following worker properties:
 * </p>
 * <ul>
 *    <li>
 *        <b>PROPERTY...</b> = Description... (Required/Optional, default: ...)
 *    </li>
 * </ul>
 *
 * @author ...
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

        // Get the authentication information from requestContext
        // TODO: Extract cookie:
        // Cookie[] cookie = requestContext.get(RequestContext.COOKIE_SOMETHING);
        // ...
        Map<String, String> cookies = new HashMap<>();
        cookies.put("SWS_ENV_OPERATIONALMODE", "PRODUCTION");
        cookies.put("SWS_ENV_SERVER_REQUEST", "/");
        cookies.put("SWS_ENV_REMOTE_ADDR", "46.140.94.220");
        cookies.put("SWS_ENV_SERVER_ADDR", "x.x.x.x");
        
        final LogMap logMap = LogMap.getInstance(requestContext);
        
        // TODO: Add business logic for processing the cookies and add them to logMap
        
        logMap.putAll(cookies);
    }

    @Override
    public List<String> getFatalErrors() {
        return configErrors;
    }

}
