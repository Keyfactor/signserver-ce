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
import java.security.PrivateKey;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
    private static final String TEST_ISSUER2 = "issuer2";
    private static final String TEST_SUBJECT1 = "subject1";
    private static KeyPair keyPair;
    private static KeyPair keyPair2;
    
    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void beforeTests() throws Exception {
        keyPair = CryptoUtils.generateRSA(2048);
        keyPair2 = CryptoUtils.generateRSA(2048);
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
     * Test that ommitting AUTHJWTn.CLAIM.NAME results in an appropriate
     * error message.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testNoClaimNameError() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHJWT1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT1.CLAIM.VALUE", "value");
        instance.init(42, config, null);

        final List<String> fatalErrors = instance.getFatalErrors();

        assertTrue("Contains error: " + fatalErrors.toString(),
                   fatalErrors.contains("CLAIM.NAME and CLAIM.VALUE needs to be specified for AUTHJWT rules"));
    }

    /**
     * Test that ommitting AUTHJWTn.CLAIM.VALUE results in an appropriate
     * error message.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testNoClaimValueError() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHJWT1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT1.CLAIM.NAME", "groups");
        instance.init(42, config, null);

        final List<String> fatalErrors = instance.getFatalErrors();

        assertTrue("Contains error: " + fatalErrors.toString(),
                   fatalErrors.contains("CLAIM.NAME and CLAIM.VALUE needs to be specified for AUTHJWT rules"));
    }

    /**
     * Test that ommitting AUTHJWTn.CLAIM.NAME and .CLAIM.VALUE results in an appropriate
     * error message.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testNoClaimNameAndValueError() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHJWT1.ISSUER", TEST_ISSUER1);
        instance.init(42, config, null);

        final List<String> fatalErrors = instance.getFatalErrors();

        assertTrue("Contains error: " + fatalErrors.toString(),
                   fatalErrors.contains("CLAIM.NAME and CLAIM.VALUE needs to be specified for AUTHJWT rules"));
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
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
                    
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
        
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        generateToken(keyPair.getPrivate(), TEST_ISSUER1,
                                      System.currentTimeMillis(), claims));
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

    /**
     * Test authorizing with a valid token for another issuer.
     * Should not be authorized.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidTokenOtherIssuer() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTH_SERVER_1.ISSUER", TEST_ISSUER2);
        config.setProperty("AUTH_SERVER_1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT1.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT1.CLAIM.VALUE", "scope1");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
            
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
        
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        generateToken(keyPair.getPrivate(), TEST_ISSUER1,
                                      System.currentTimeMillis(), claims));
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            assertEquals("Exception message", "Authorization failed: Unknown issuer", e.getMessage());
        }
    }

    /**
     * Test authorizing with a valid token issued by a non-trusted CA.
     * Should not be authorized.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidTokenOtherPublicKey() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTH_SERVER_1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTH_SERVER_1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
            
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
        
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        generateToken(keyPair2.getPrivate(), TEST_ISSUER2,
                                      System.currentTimeMillis(), claims));
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            assertEquals("Exception message", "Authorization failed: Unknown issuer", e.getMessage());
        }
    }

    /**
     * Test that authorization fails with an expired token using the default
     * max allowed clock scew.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidTokenExpiredDefaultScew() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTH_SERVER_1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTH_SERVER_1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
            final long issuedAt = System.currentTimeMillis() - 360000; // 6 min
            
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
        
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        generateToken(keyPair.getPrivate(), TEST_ISSUER1,
                                      issuedAt, claims));
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            assertTrue("Exception message: " + e.getMessage(), e.getMessage().contains("Authorization failed"));
            assertTrue("Exception message: " + e.getMessage(), e.getMessage().contains("expired"));
        }
    }

    /**
     * Test that authorization succeeds with a token within the default
     * max allowed clock scew.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidTokenWithinDefaultScew() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTH_SERVER_1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTH_SERVER_1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
            final long issuedAt = System.currentTimeMillis() - 240000; // 4 min
            
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
        
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        generateToken(keyPair.getPrivate(), TEST_ISSUER1,
                                      issuedAt, claims));
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            fail("Should be authorized");
        }
    }

    /**
     * Test that authorization fails with an expired token using a shorter
     * allowed max clock scew.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidExpiredShortAllowedScew() throws Exception {
        final JWTAuthorizer instance = new JWTAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTH_SERVER_1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTH_SERVER_1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        config.setProperty("MAX_ALLOWED_CLOCK_SCEW", "60");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
            final long issuedAt = System.currentTimeMillis() - 120000; // 2 min
            
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
        
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        generateToken(keyPair.getPrivate(), TEST_ISSUER1,
                                      issuedAt, claims));
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            assertTrue("Exception message: " + e.getMessage(), e.getMessage().contains("Authorization failed"));
            assertTrue("Exception message: " + e.getMessage(), e.getMessage().contains("expired"));
        }
    }

    private String generateToken(final PrivateKey privKey, final String issuer,
                                 final long issuedAt, Map<String, Object> claims) {
        final SignatureAlgorithm sigAlg = SignatureAlgorithm.RS256;
        final JwtBuilder builder = Jwts.builder().setId("id")
                .setIssuedAt(new Date(issuedAt))
                .setSubject(TEST_SUBJECT1)
                .setIssuer(issuer)
                .setExpiration(new Date(issuedAt + 10000))
                .setHeaderParam("typ", "JWT")
                .addClaims(claims)
                .signWith(privKey, sigAlg);

        return builder.compact();
    }
}
