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
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.server.IAuthorizer;
import org.signserver.server.UsernamePasswordClientCredential;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;

/**
 * Sample username/password authorizer allowing any user to connect using
 * any username and the username in reverse as the password.
 * <p>
 * The authorizer has the following worker properties:
 * </p>
 * <ul>
 *    <li>
 *        <b>REVERSED_PASSWORD</b> = If the password should be the username in
 *           reverse, if not it is simply the username
 *           (Optional, default: "true")
 *    </li>
 * </ul>
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ReversedNameAuthorizer implements IAuthorizer {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(ReversedNameAuthorizer.class);

    // Worker properties
    public static final String PROPERTY_REVERSED_PASSWORD = "REVERSED_PASSWORD";

    // Log fields

    // Default values
    private static final boolean DEFAULT_REVERSED_PASSWORD = true;

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private boolean reversedPassword;

    @Override
    public void init(int workerId, WorkerConfig config, EntityManager em)
            throws SignServerException {
        // Optional property REVERSED_PASSWORD
        final String value = config.getProperty(PROPERTY_REVERSED_PASSWORD,
                String.valueOf(DEFAULT_REVERSED_PASSWORD));
        if (Boolean.TRUE.toString().equalsIgnoreCase(value)) {
            reversedPassword = true;
        } else if (Boolean.FALSE.toString().equalsIgnoreCase(value)) {
            reversedPassword = false;
        } else {
            configErrors.add("Incorrect value for property "
                    + PROPERTY_REVERSED_PASSWORD);
        }
    }

    @Override
    public void isAuthorized(Request request,
            RequestContext requestContext) throws IllegalRequestException,
                SignServerException {
        final Object o = requestContext.get(RequestContext.CLIENT_CREDENTIAL_PASSWORD);

        if (o instanceof UsernamePasswordClientCredential) {
            final UsernamePasswordClientCredential credentials
                    = (UsernamePasswordClientCredential) o;
            final String username = credentials.getUsername();
            final String password;

            // If the password should be the reversed username or just username
            if (reversedPassword) {
                password = StringUtils.reverse(username);
            } else {
                password = username;
            }

            // Check the username and password
            if (username == null || username.trim().isEmpty()
                    || !password.equals(credentials.getPassword())) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authentication denied for user " + username);
                }
                throw new AuthorizationRequiredException(
                        "Authentication denied");
            }

            // Put the authorized username in the log
            LogMap.getInstance(requestContext).put(IAuthorizer.LOG_USERNAME,
                    new Loggable() {
                        @Override
                        public String toString() {
                            return username;
                        }
                    });
        } else {
            throw new AuthorizationRequiredException(
                    "Username/password authentication required");
        }
    }

    @Override
    public List<String> getFatalErrors() {
        return configErrors;
    }

}
