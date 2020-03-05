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

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.KeyPair;
import java.security.Security;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.signserver.common.AuthorizationRequiredException;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.test.utils.builders.CryptoUtils;

/**
 * Unit tests for JWTAuthorizer.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class JWTAuthorizerUnitTest {

    private static final String TEST_ISSUER1 = "issuer1";
    private static final String TEST_SUBJECT1 = "subject1";
    private static KeyPair keyPair;
    
    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void beforeTests() throws Exception {
        keyPair = CryptoUtils.generateRSA(2048);
    }
    
    /**
     * Test that setting an illegal value for MAX_ALLOWED_CLOCK_SCEW
     * results in an error message.
     *
     * @throws Exception 
     */
    @Test
    public void testIllegalMaxAllowedClockScew() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MAX_ALLOWED_CLOCK_SCEW", "foobar123");
        instance.init(42, config, null);

        final List<String> fatalErrors = instance.getFatalErrors();

        assertTrue("Contains error: " + fatalErrors.toString(),
                   fatalErrors.contains("Illegal value for MAX_ALLOWED_CLOCK_SCEW: foobar123"));
    }

    /**
     * Test that setting a negative value for MAX_ALLOWED_CLOCK_SCEW
     * results in an error message.
     *
     * @throws Exception 
     */
    @Test
    public void testNegativeMaxAllowedClockScew() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MAX_ALLOWED_CLOCK_SCEW", "-1");
        instance.init(42, config, null);

        final List<String> fatalErrors = instance.getFatalErrors();

        assertTrue("Contains error: " + fatalErrors.toString(),
                   fatalErrors.contains("MAX_ALLOWED_CLOCK_SCEW must be positive"));
    }

    /**
     * Test that setting a valid value for MAX_ALLOWED_CLOCK_SCEW works.
     *
     * @throws Exception 
     */
    @Test
    public void testLegalMaxAllowedClockScew() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("MAX_ALLOWED_CLOCK_SCEW", "60");
        instance.init(42, config, null);

        final List<String> fatalErrors = instance.getFatalErrors();

        assertTrue("Contains no error: " + fatalErrors.toString(),
                   fatalErrors.isEmpty());
    }

    /**
     * Test authorizing with a valid token.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidToken() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTH_SERVER_1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTH_SERVER_1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
        
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER, generateToken());
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            fail("Should be authorized");
        }
    }

    /**
     * Test that we get "Authorization required" when there's no token in the
     * request.
     *
     * @throws Exception 
     */
    @Test
    public void testNoToken() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTH_SERVER_1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTH_SERVER_1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();

            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            assertEquals("Exception message", "Authorization required",
                         e.getMessage());
        }
    }

    private String generateToken() {
        final SignatureAlgorithm sigAlg = SignatureAlgorithm.RS256;
        final long nowMs = System.currentTimeMillis();
        final Date now = new Date(nowMs);
        final Date exp = new Date(nowMs + 10000); // 10 s
        final JwtBuilder builder = Jwts.builder().setId("id")
                .setIssuedAt(now)
                .setSubject(TEST_SUBJECT1)
                .setIssuer(TEST_ISSUER1)
                .setExpiration(exp)
                .signWith(keyPair.getPrivate(), sigAlg);

        return builder.compact();
    }
}
