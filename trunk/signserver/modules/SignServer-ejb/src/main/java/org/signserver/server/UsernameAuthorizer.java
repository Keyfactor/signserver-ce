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

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;

/**
 * Authorizer requiring only a username (and no password as that is assumed to
 * already have been checked by a proxy for instance).
 *
 * <p>
 * Properties: ACCEPT_USERNAMES, ACCEPT_ALL_USERNAMES
 * </p>
 *
 * <pre>
 * Form 1, ACCEPT_ALL_USERNAMES = false (default) and usernames are specified:
 * ACCEPT_ALL_USERNAMES = false
 * ACCEPT_USERNAMES = user1;user2;user3
 *
 * Form 2, ACCEPT_ALL_USERNAMES = true and no usernames are specified:
 * ACCEPT_ALL_USERNAMES = true
 * </pre>
 *
 * @version $Id$
 */
public class UsernameAuthorizer implements IAuthorizer {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            UsernameAuthorizer.class);

    /** Property AUTHORIZED_USERNAMES. */
    private static final String ACCEPT_USERNAMES = "ACCEPT_USERNAMES";
    
    /** Property ACCEPT_ALL_USERNAMES */
    private static final String ACCEPT_ALL_USERNAMES = "ACCEPT_ALL_USERNAMES";

    /** Set with all the accepted usernames. */
    private Set<String> acceptUsernames = Collections.emptySet();

    /** True if all usernames should be accepted */
    private boolean acceptAllUsernames;

    private String configError;
    
    /**
     * Initializes this Authorizer.
     * @param workerId
     * @param config
     * @param em
     * @throws SignServerException
     */
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final EntityManager em)
            throws SignServerException {

        acceptAllUsernames =
                Boolean.parseBoolean(config.getProperty(ACCEPT_ALL_USERNAMES));
        final String usernames = config.getProperty(ACCEPT_USERNAMES);

        if (acceptAllUsernames && usernames != null) {
            configError = "Can not specify both ACCEPT_ALL_USERNAMES=true and ACCEPT_USERNAMES";
            throw new SignServerException(configError);
        } else if(!acceptAllUsernames) {
            configError = null;
            loadAccounts(usernames);
        }
    }

    @Override
    public void isAuthorized(final Request request,
            final RequestContext requestContext)
            throws SignServerException, IllegalRequestException {

        final Object o = requestContext.get(RequestContext.CLIENT_CREDENTIAL_PASSWORD);
        
        if (o instanceof UsernamePasswordClientCredential) {

            if (!isAuthorized((UsernamePasswordClientCredential) o)) {
                throw new AuthorizationRequiredException(
                        "Authentication denied");
            }

            // Put the authorized username in the log
            logUsername(((UsernamePasswordClientCredential) o).getUsername(),
                    requestContext);
        } else {
            throw new AuthorizationRequiredException(
                    "Username required");
        }
    }

    private static boolean isValidUsername(final String username) {
        return username != null && username.length() > 0;
    }
    
    private void loadAccounts(final String value) {
        LOG.trace(">loadAccounts");

        acceptUsernames = new HashSet<>();

        if (value == null) {
            LOG.warn("No ACCEPT_USERNAMES specified");
        } else {
            for (String name : value.split(";")) {
                name = name.trim();
                if (isValidUsername(name)) {
                   acceptUsernames.add(name);
                } else {
                    LOG.warn("Invalid username configured: \"" + name + "\"");
                }
            }
        }
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Usernames configured: " + acceptUsernames.size());
        }
        LOG.trace("<loadAccounts");
    }

    private boolean isAuthorized(
            final UsernamePasswordClientCredential credential) {
        return isValidUsername(credential.getUsername()) && (acceptAllUsernames
                || acceptUsernames.contains(credential.getUsername()));
    }

    private static void logUsername(final String username,
            final RequestContext requestContext) {
        LogMap.getInstance(requestContext).put(IAuthorizer.LOG_USERNAME,
                    new Loggable() {
                        @Override
                        public String toString() {
                            return username;
                        }
                    });
    }

    @Override
    public List<String> getFatalErrors() {
        final LinkedList<String> fatalErrors = new LinkedList<>();
        if (configError != null) {
            fatalErrors.add(configError);
        }
        return fatalErrors;
    }
}
