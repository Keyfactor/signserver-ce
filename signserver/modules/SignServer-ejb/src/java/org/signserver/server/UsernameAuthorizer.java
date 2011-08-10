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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;

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
    
    private int workerId;
    private ProcessableConfig config;

    /** True if all usernames should be accepted */
    private boolean acceptAllUsernames;

    /**
     * Initializes this Authorizer.
     * @param workerId
     * @param config
     * @param em
     * @throws SignServerException
     */
    public void init(final int workerId, final WorkerConfig config,
            final EntityManager em)
            throws SignServerException {
        this.config = new ProcessableConfig(config);
        this.workerId = workerId;

        acceptAllUsernames =
                Boolean.parseBoolean(config.getProperty(ACCEPT_ALL_USERNAMES));
        final String usernames = config.getProperty(ACCEPT_USERNAMES);

        if (acceptAllUsernames && usernames != null) {
            throw new SignServerException(
                "Can not specify both ACCEPT_ALL_USERNAMES=true and ACCEPT_USERNAMES");
        } else if(!acceptAllUsernames) {
            loadAccounts(usernames);
        }
    }

    public void isAuthorized(final ProcessRequest request,
            final RequestContext requestContext)
            throws SignServerException, IllegalRequestException {

        final Object o = requestContext.get(RequestContext.CLIENT_CREDENTIAL);
        
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

        acceptUsernames = new HashSet<String>();

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
        Map<String, String> logMap = (Map)
                requestContext.get(RequestContext.LOGMAP);
        if (logMap == null) {
            logMap = new HashMap<String, String>();
            requestContext.put(RequestContext.LOGMAP, logMap);
        }
        logMap.put(IAuthorizer.LOG_USERNAME, username);
    }

}
