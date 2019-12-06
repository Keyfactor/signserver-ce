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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.server.log.LogMap;
import org.signserver.server.log.Loggable;

/**
 * Authorizer requiring a username password pair.
 * 
 * @version $Id$
 */
public class UsernamePasswordAuthorizer implements IAuthorizer {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            UsernamePasswordAuthorizer.class);
    /**
     * Format for a user entry is:
     * <pre>
     * USER.[NAME] = [PASSWORD]
     * USER.[NAME] = [HASHED_PASSWORD]:[HASH_ALGORITHM]
     * USER.[NAME] = [HASHED_PASSWORD]:[HASH_ALGORITHM]:[SALT]
     * </pre>
     * SALT and HASH_ALGORITHM are optionally.
     */
    private static final String USER_PREFIX = "USER.";

    private Map<String, Account> userMap = Collections.emptyMap();

    
    @Override
    public void init(final int workerId, final WorkerConfig config,
            final EntityManager em)
            throws SignServerException {
        loadAccounts(config);
    }
    
    @Override
    public List<String> getFatalErrors() {
        return Collections.emptyList();
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
                    "Username/password authentication required");
        }
    }

    private void loadAccounts(final WorkerConfig config) {

        userMap = new HashMap<>();

        for(Object o : config.getProperties().keySet()) {
            if (o instanceof String) {
                final String key = (String) o;
                if (key.startsWith(USER_PREFIX)
                        && key.length() > USER_PREFIX.length()) {

                    final String value = config.getProperties().getProperty(key);
                    final String[] parts = value.split(":");
                    final String password;
                    String digestAlgorithm = null;
                    final MessageDigest digest;
                    String salt = "";
                    password = parts[0];
                    if (parts.length > 1) {
                        digestAlgorithm = parts[1];
                        if (parts.length > 2) {
                            salt = parts[2];
                        }
                    }
                    try {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Loading account: " + key);
                        }

                        digest = digestAlgorithm == null ? null
                                : MessageDigest.getInstance(digestAlgorithm, "BC");

                        userMap.put(key.substring(USER_PREFIX.length()).toUpperCase(),
                                new Account(password, salt, digest));

                    } catch (NoSuchAlgorithmException ex) {
                        LOG.error("Unsupported digest algorithm: "
                                    + digestAlgorithm, ex);
                    } catch (NoSuchProviderException ex) {
                        LOG.error("No BC provider getting digest algorithm",
                            ex);
                    }
                }
            }
        }
    }

    private boolean isAuthorized(
            final UsernamePasswordClientCredential credential) {
        final boolean result;

        if (credential.getUsername() == null
                || credential.getUsername().isEmpty()) {
            result = false;
        } else {
            final Account a = userMap.get(credential.getUsername().toUpperCase());
            if (a == null) {
                if (LOG.isInfoEnabled()) {
                    LOG.info("No such user: " + credential.getUsername());
                }
                result = false;
            } else {

                String password = credential.getPassword() + a.getSalt();
                if (a.getDigest() != null) {
                    a.getDigest().reset();
                    password = new String(Hex.encode(a.getDigest().digest(password.getBytes())));
                }
                result = password.equals(a.getPassword());
            }
        }
        return result;
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

    private static class Account {

        private String password;
        private String salt;
        private MessageDigest digest;

        public Account(final String password, final String salt,
                final MessageDigest digest) {
            this.password = password;
            this.salt = salt;
            this.digest = digest;
        }

        public MessageDigest getDigest() {
            return digest;
        }

        public String getPassword() {
            return password;
        }

        public String getSalt() {
            return salt;
        }
    }
}
