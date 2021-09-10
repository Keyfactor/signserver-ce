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
package org.signserver.testutils;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.PrivateKey;
import java.util.Date;
import java.util.Map;

/**
 * Test utilities for JWT.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class JwtUtils {

    /**
     * Generates a JWT string.
     * @param privateKey Private key.
     * @param signatureAlgorithm Signature algorithm.
     * @param issuer Issuer.
     * @param issuedAt Issue time.
     * @param subject Token's subject.
     * @param claims Token's claims.
     * @return JWT string.
     */
    public static String generateToken(final PrivateKey privateKey,
                                       final SignatureAlgorithm signatureAlgorithm,
                                       final String issuer,
                                       final long issuedAt,
                                       final String subject,
                                       final Map<String, Object> claims) {
        final JwtBuilder builder = Jwts.builder()
                .setId("id")
                .setIssuedAt(new Date(issuedAt))
                .setSubject(subject)
                .setIssuer(issuer)
                .setExpiration(new Date(issuedAt + 10000))
                .setHeaderParam("typ", "JWT")
                .addClaims(claims)
                .signWith(privateKey, signatureAlgorithm);

        return builder.compact();
    }
}
