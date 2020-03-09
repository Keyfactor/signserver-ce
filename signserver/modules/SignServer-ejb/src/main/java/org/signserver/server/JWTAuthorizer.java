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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.persistence.EntityManager;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;
import org.signserver.server.jwtauth.JwtMatchingRule;

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
 * @author Marcus Lundblad
 * @version $Id$
 */
public class JWTAuthorizer implements IAuthorizer {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(JWTAuthorizer.class);

    // Worker properties
    private final String AUTH_SERVER_PREFIX = "AUTH_SERVER_";
    private final String ISSUER_SUFFIX = ".ISSUER";
    private final String PUBLICKEY_SUFFIX = ".PUBLICKEY";
    private final String AUTHJWT_PREFIX = "AUTHJWT";
    private final String CLAIM_NAME_SUFFIX = ".CLAIM.NAME";
    private final String CLAIM_VALUE_SUFFIX = ".CLAIM.VALUE";
    private final String DESCRIPTION_SUFFIX = ".DESCRIPTION";

    private final String MAX_ALLOWED_CLOCK_SCEW = "MAX_ALLOWED_CLOCK_SCEW";
    
    // Log fields
    //...

    // Default values
    private final int DEFAULT_MAX_ALLOWED_CLOCK_SCEW = 5 * 60; // 5 minutes

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private final Map<String, PublicKey> authServers = new HashMap<>();
    private final List<JwtMatchingRule> matchRules = new ArrayList<>(2);
    private int maxAllowedClockScew;
    
    @Override
    public void init(int workerId, WorkerConfig config, EntityManager em)
            throws SignServerException {
        // Read properties
        for (final String property : config.getProperties().stringPropertyNames()) {
            if (property.startsWith(AUTH_SERVER_PREFIX) &&
                property.endsWith(ISSUER_SUFFIX)) {
                final String publicKeyProperty =
                        AUTH_SERVER_PREFIX + property.substring(AUTH_SERVER_PREFIX.length(),
                                                                property.indexOf(ISSUER_SUFFIX)) +
                        PUBLICKEY_SUFFIX;

                try {
                    final String issuer = config.getProperty(property);
                    final String publicKey = config.getProperty(publicKeyProperty);
                    authServers.put(issuer,  KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey))));
                } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                    configErrors.add("Could not parse public key " +
                                     publicKeyProperty + ": " + e.getMessage());
                }
            } else if (property.startsWith(AUTHJWT_PREFIX) &&
                       property.endsWith(ISSUER_SUFFIX)) {
                final String claimNameProperty =
                        AUTHJWT_PREFIX + property.substring(AUTHJWT_PREFIX.length(),
                                                            property.indexOf(ISSUER_SUFFIX)) +
                        CLAIM_NAME_SUFFIX;
                final String claimValueProperty =
                        AUTHJWT_PREFIX + property.substring(AUTHJWT_PREFIX.length(),
                                                            property.indexOf(ISSUER_SUFFIX)) +
                        CLAIM_VALUE_SUFFIX;
                final String descriptionProperty =
                        AUTHJWT_PREFIX + property.substring(AUTHJWT_PREFIX.length(),
                                                            property.indexOf(ISSUER_SUFFIX)) +
                        DESCRIPTION_SUFFIX;
                final String issuer = config.getProperty(property);
                final String claimName = config.getProperty(claimNameProperty);
                final String claimValue = config.getProperty(claimValueProperty);
                final String description = config.getProperty(descriptionProperty);

                if (claimName == null || claimValue == null) {
                    configErrors.add("CLAIM_NAME and CLAIM_VALUE needs to be specified for AUTHJWT rules");
                } else {
                    matchRules.add(new JwtMatchingRule(claimName, claimValue,
                                                       issuer, description));
                }
            }
        }

        final String maxAllowedClockScewString =
                    config.getProperties().getProperty(MAX_ALLOWED_CLOCK_SCEW);

        try {
            if (StringUtils.isNotBlank(maxAllowedClockScewString)) {
                maxAllowedClockScew = Integer.parseInt(maxAllowedClockScewString);
                if (maxAllowedClockScew < 0) {
                    configErrors.add(MAX_ALLOWED_CLOCK_SCEW + " must be positive");
                }
            } else {
                maxAllowedClockScew = DEFAULT_MAX_ALLOWED_CLOCK_SCEW;
            }
        } catch (NumberFormatException e) {
            configErrors.add("Illegal value for " + MAX_ALLOWED_CLOCK_SCEW +
                             ": " + maxAllowedClockScewString);
        }
    }

    @Override
    public void isAuthorized(Request request,
            RequestContext requestContext) throws IllegalRequestException,
            SignServerException {
        final String bearerToken =
                (String) requestContext.get(RequestContext.CLIENT_CREDENTIAL_BEARER);
        
        if (bearerToken == null) {
            throw new AuthorizationRequiredException("Authorization required");
        }
        
        if (!validateToken(bearerToken)) {
            throw new AuthorizationRequiredException("Not authorized");
        }
    }

    private boolean validateToken(String token) {
        // Verification
        try {
            Jws<Claims> jws = Jwts.parserBuilder().setSigningKeyResolver(new SigningKeyResolverAdapter() {

                @Override
                public Key resolveSigningKey(JwsHeader header, Claims claims) {
                    final PublicKey result = authServers.get(claims.getIssuer());
                    if (result == null) {
                        throw new JwtException("Unknown issuer");
                    }
                    return result;
                }

            }).setAllowedClockSkewSeconds(maxAllowedClockScew).build().parseClaimsJws(token);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Header: " + jws.getHeader());
                LOG.debug("Body: " + jws.getBody());
                LOG.debug("Subject: " + jws.getBody().getSubject());
                LOG.debug("Audiance: " + jws.getBody().getAudience());

                LOG.debug("** Checking algorithm **");
                LOG.debug("Algorithm: " + jws.getHeader().getAlgorithm());
            }

            if (!"none".equalsIgnoreCase(jws.getHeader().getAlgorithm())) {
                LOG.debug("Algorithm is not none");
            } else {
                LOG.debug("Unsigned token!");
                return false;
            }

            if ("JWT".equals(jws.getHeader().getType())) {
                LOG.debug("Type is expected JWT");
            } else {
                LOG.debug("Unexpected type!");
                return false;
            }

            if (jws.getBody().getAudience() == null) {
                LOG.debug("Accepting token as no specific audiance specified");
            } else {
                LOG.error("Not for us!");
                return false;
            }

            if ("airhacks".equals(jws.getBody().getIssuer())) {
                System.out.println("Issuer is ok");
            }

            System.out.println("** Match on subject **");
            final boolean subjectIsDuke = "duke".equals(jws.getBody().getSubject());
            System.out.println("Is authorized as subject is duke: " + subjectIsDuke);

            System.out.println("** Match on groups **");
            final List<String> groups = jws.getBody().get("groups", List.class);
            final boolean groupsContainsChief = groups != null && groups.contains("chief");
            System.out.println("Is authorized as groups contains chief: " + groupsContainsChief);
            return true;
        } catch (JwtException ex) {
            LOG.error("JWT validation failed", ex);
            return false;
        }
        
    }

    @Override
    public List<String> getFatalErrors() {
        return configErrors;
    }

}
