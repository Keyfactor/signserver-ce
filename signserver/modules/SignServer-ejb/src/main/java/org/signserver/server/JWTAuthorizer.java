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
import io.jsonwebtoken.JwtParser;
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
    private JwtParser jwtParser;
    
    @Override
    public void init(int workerId, WorkerConfig config, EntityManager em)
            throws SignServerException {
        // Read properties
        config.getProperties().stringPropertyNames().forEach((property) -> {
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
                    configErrors.add("CLAIM.NAME and CLAIM.VALUE needs to be specified for AUTHJWT rules");
                } else {
                    matchRules.add(new JwtMatchingRule(claimName, claimValue,
                            issuer, description));
                }
            }
        });
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Authorization rules: " + matchRules);
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
        
        // Create JWT parser
        jwtParser = Jwts.parserBuilder().setSigningKeyResolver(new SigningKeyResolverAdapter() {
            
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                final PublicKey result = authServers.get(claims.getIssuer());
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unknown issuer: " + claims.getIssuer());
                }
                if (result == null) {
                    throw new JwtException("Unknown issuer");
                }
                return result;
            }

        }).setAllowedClockSkewSeconds(maxAllowedClockScew).build();
    }

    @Override
    public void isAuthorized(Request request,
            RequestContext requestContext) throws IllegalRequestException,
            SignServerException {
        final String bearerToken =
                (String) requestContext.get(RequestContext.CLIENT_CREDENTIAL_BEARER);
        // Check configuration
        if (!configErrors.isEmpty()) {
            throw new SignServerException("Component is misconfigured");
        }
        
        // Token available?
        if (bearerToken == null) {
            throw new AuthorizationRequiredException("Authorization required");
        }
        
        try {
            // Validate token
            final Jws<Claims> jws = validateToken(bearerToken);
            
            // Find matching rule
            final JwtMatchingRule matchedRule = findMatchingRule(jws.getBody());
            if (matchedRule == null) {
                throw new AuthorizationRequiredException("Not authorized");
            }
            
            // Put the authorized username in the log
            logUsername(jws.getBody().getSubject(), requestContext);
        } catch (JwtException ex) {
            throw new AuthorizationRequiredException("Authorization failed: " + ex.getLocalizedMessage(), ex);
        }
    }

    /**
     * Parses and returns the validated token.
     *
     * @param token in textual (i.e. JSON) representation to parse
     * @return the parsed and validated token
     * @throws JwtException in case of failure to validate the token
     */
    protected final Jws<Claims> validateToken(String token) throws JwtException {
        // Parse JWS
        final Jws<Claims> jws = jwtParser.parseClaimsJws(token);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Header: " + jws.getHeader() 
                    + "\nBody: " + jws.getBody());
        }

        // Extra check for none as algorithm
        if ("none".equalsIgnoreCase(jws.getHeader().getAlgorithm())) {
            throw new JwtException("Algorithm is none");
        }

        // Extra check for type
        if (!"JWT".equals(jws.getHeader().getType())) {
            throw new JwtException("Token type is not JWT");
        }

        // Extra check for audiance.
        // TODO: Later: Should be configurable?
        if (jws.getBody().getAudience() != null) {
            throw new JwtException("Specific audience specified");
        }

        return jws;
    }

    /**
     * Get the first rule that matches the given claims or null if no match
     * could be found.
     *
     * @param claims (i.e. token body) to match against
     * @return The matched rule or null if no match was found
     */
    protected final JwtMatchingRule findMatchingRule(final Claims claims) {
        JwtMatchingRule result = null;
        for (JwtMatchingRule rule : matchRules) {
            // Check that issuer matches
            if (rule.getIssuer().equals(claims.getIssuer())) {
                // Check if we find the claim and contains the value or equals the value
                Object claim = claims.get(rule.getClaimName());
                if (claim instanceof List) {
                    final List<String> claimValues = (List<String>) claim;
                    if (claimValues.contains(rule.getClaimValue())) {
                        result = rule;
                        break;
                    }
                } else if (claim != null && claim.toString().equals(rule.getClaimValue())) {
                    result = rule;
                    break;
                }
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Matched rule: " + result);
        }
        return result;
    }

    @Override
    public List<String> getFatalErrors() {
        return configErrors;
    }

    private static void logUsername(final String username,
            final RequestContext requestContext) {
        LogMap.getInstance(requestContext).put(IAuthorizer.LOG_USERNAME, username);
    }
}
