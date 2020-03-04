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
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.persistence.EntityManager;
import org.apache.log4j.Logger;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;

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

    // Log fields
    //...

    // Default values
    //...

    // Configuration errors
    private final LinkedList<String> configErrors = new LinkedList<>();

    // Configuration values
    private final Map<String, PublicKey> authServers = new HashMap<>();

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
            }
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

            }).setAllowedClockSkewSeconds(60*60*24).build().parseClaimsJws(token);
            System.out.println("Header: " + jws.getHeader());
            System.out.println("Body: " + jws.getBody());
            System.out.println("Subject: " + jws.getBody().getSubject());
            System.out.println("Audiance: " + jws.getBody().getAudience());

            System.out.println("** Checking algorithm **");
            System.out.println("Algorithm: " + jws.getHeader().getAlgorithm());
            if (!"none".equalsIgnoreCase(jws.getHeader().getAlgorithm())) {
                System.out.println("Algorithm is not none");
            } else {
                System.out.println("Unsigned token!");
            }

            System.out.println("** Checking type **");
            if ("JWT".equals(jws.getHeader().getType())) {
                System.out.println("Type is expected JWT");
            } else {
                System.err.println("Unexpected type!");
            }

            System.out.println("** Check audiance **");
            if (jws.getBody().getAudience() == null) {
                System.out.println("Accepting token as no specific audiance specified");
            } else {
                System.err.println("Not for us!");
            }

            System.out.println("** Checking issuer **");
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
