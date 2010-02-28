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
import java.util.Map;

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
 * Authorizer requiring a username password pair.
 * 
 *
 * @version $Id$
 */
public class UsernamePasswordAuthorizer implements IAuthorizer {

    private static final Logger LOG = Logger.getLogger(
            UsernamePasswordAuthorizer.class);
    /**
     * Format for a user entry is:
     * <pre>
     * USER.[NAME] = [HASHED_PASSWORD]:[SALT]:[DIGEST_ALGORITHM]
     * </pre>
     * SALT and DIGEST_ALGORITHMS are optionally.
     */
    private static final String USER_PREFIX = "USER.";


    private Map<String, Password> userMap = Collections.emptyMap();
    
    private int workerId;
    private ProcessableConfig config;

    
    public void init(final int workerId, final WorkerConfig config,
            final EntityManager em)
            throws SignServerException {
        this.config = new ProcessableConfig(config);
        this.workerId = workerId;

        loadPasswords(config);
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
        } else {
            throw new AuthorizationRequiredException(
                    "Username/password authentication required");
        }
    }

    private void loadPasswords(final WorkerConfig config) {

        userMap = new HashMap<String, Password>();

        for(Object o : config.getProperties().keySet()) {
            if (o instanceof String) {
                final String key = (String) o;
                if (key.startsWith(USER_PREFIX)
                        && key.length() > USER_PREFIX.length()) {

                    final String value = config.getProperties().getProperty(key);
                    final String[] parts = value.split(":");
                    final String password;
                    String salt = "";
                    String digestAlgorithm = null;
                    password = parts[0];
                    if (parts.length > 1) {
                        salt = parts[1];
                        if (parts.length > 2) {
                            digestAlgorithm = parts[2];

                            // Currently no digest algorithm is supported
                            // TODO: Check agains list of supported algorithms
                            if (!digestAlgorithm.isEmpty()) {
                                LOG.error("Unsupported digest algorithm: "
                                        + digestAlgorithm);
                            }
                        }
                    }
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Key: " + key);
                    }
                    userMap.put(key.substring(USER_PREFIX.length()).toUpperCase(),
                            new Password(password, salt, digestAlgorithm));
                }
            }
        }
    }

    private boolean isAuthorized(
            final UsernamePasswordClientCredential credential) {
        final boolean result;

        if (credential.getUsername() == null) {
            result = false;
        } else {
            final Password p = userMap.get(credential.getUsername().toUpperCase());
            if (p == null) {
                result = false;
            } else {
                // TODO: Add support for hashing and salting here
                // Now we use clear-textpasswords only
                result = p.getPassword().equals(credential.getPassword());
            }
        }
        return result;
    }

    private static class Password {

        private String password;
        private String salt;
        private String digestAlgorithm;

        public Password(final String password, final String salt,
                final String digestAlgorithm) {
            this.password = password;
            this.salt = salt;
            this.digestAlgorithm = digestAlgorithm;
        }

        public String getDigestAlgorithm() {
            return digestAlgorithm;
        }

        public String getPassword() {
            return password;
        }

        public String getSalt() {
            return salt;
        }
    }
}
