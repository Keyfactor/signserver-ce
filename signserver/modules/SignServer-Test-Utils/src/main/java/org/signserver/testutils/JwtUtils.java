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
     * 
     * @param privKey
     * @param signatureAlgorithm
     * @param issuer
     * @param issuedAt
     * @param subject
     * @param claims
     * @return 
     */
    public static String generateToken(final PrivateKey privKey,
                                       final SignatureAlgorithm signatureAlgorithm,
                                       final String issuer,
                                       final long issuedAt,
                                       final String subject,
                                       final Map<String, Object> claims) {
        final JwtBuilder builder = Jwts.builder().setId("id")
                .setIssuedAt(new Date(issuedAt))
                .setSubject(subject)
                .setIssuer(issuer)
                .setExpiration(new Date(issuedAt + 10000))
                .setHeaderParam("typ", "JWT")
                .addClaims(claims)
                .signWith(privKey, signatureAlgorithm);

        return builder.compact();
    }
}
