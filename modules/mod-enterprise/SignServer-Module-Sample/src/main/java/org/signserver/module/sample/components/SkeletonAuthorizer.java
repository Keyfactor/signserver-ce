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
package org.signserver.module.sample.components;

import java.util.LinkedList;
import java.util.List;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.server.IAuthorizer;

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
public class SkeletonAuthorizer implements IAuthorizer {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(SkeletonAuthorizer.class);

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
        // ...
        
        throw new AuthorizationRequiredException("Not authorized");
    }

    @Override
    public List<String> getFatalErrors() {
        return configErrors;
    }

}
