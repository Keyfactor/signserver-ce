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
package org.signserver.server.jwtauth;

import org.signserver.testutils.JwtUtils;
import io.jsonwebtoken.SignatureAlgorithm;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.log4j.Logger;
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
public class JwtAuthorizerUnitTest {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(JwtAuthorizerUnitTest.class);

    private static final String TEST_ISSUER1 = "issuer1";
    private static final String TEST_ISSUER2 = "issuer2";
    private static final String TEST_SUBJECT1 = "subject1";
    private static KeyPair keyPair;
    private static KeyPair keyPair2;
    private static KeyPair keyPair3;
    
    @BeforeClass
    public static void setUpClass() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void beforeTests() throws Exception {
        keyPair = CryptoUtils.generateRSA(2048);
        keyPair2 = CryptoUtils.generateRSA(2048);
        keyPair3 = CryptoUtils.generateEcCurve("secp256r1");
    }
    
    /**
     * Test that setting an illegal value for MAX_ALLOWED_CLOCK_SCEW
     * results in an error message.
     *
     * @throws Exception 
     */
    @Test
    public void testIllegalMaxAllowedClockScew() throws Exception {
        LOG.info("testIllegalMaxAllowedClockScew");

        final JwtAuthorizer instance = new JwtAuthorizer();
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
        LOG.info("testNegativeMaxAllowedClockScew");

        final JwtAuthorizer instance = new JwtAuthorizer();
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
        LOG.info("testLegalMaxAllowedClockScew");

        final JwtAuthorizer instance = new JwtAuthorizer();
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
        LOG.info("testNoClaimNameError");

        final JwtAuthorizer instance = new JwtAuthorizer();
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
        LOG.info("testNoClaimValueError");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHJWT1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT1.CLAIM.NAME", "groups");
        instance.init(42, config, null);

        final List<String> fatalErrors = instance.getFatalErrors();

        assertTrue("Contains error: " + fatalErrors.toString(),
                   fatalErrors.contains("CLAIM.NAME and CLAIM.VALUE needs to be specified for AUTHJWT rules"));
    }

    /**
     * Test that omitting AUTHJWTn.CLAIM.NAME and .CLAIM.VALUE results in an appropriate
     * error message.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testNoClaimNameAndValueError() throws Exception {
        LOG.info("testNoClaimNameAndValueError");

        final JwtAuthorizer instance = new JwtAuthorizer();
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
        LOG.info("testValidToken");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER4.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER4.PUBLICKEY",
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
                        JwtUtils.generateToken(keyPair.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER1,
                                               System.currentTimeMillis(),
                                               TEST_SUBJECT1, claims));
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            fail("Should be authorized");
        }
    }

    /**
     * Test authorizing with a valid token with a list of audiences in the token
     * and a list a of accepted audiences containing these.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidTokenWithAudience() throws Exception {
        LOG.info("testValidTokenWithAudience");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        config.setProperty("ACCEPTED_AUDIENCES", "service1, service2");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
                    
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
            claims.put("aud", Arrays.asList("service1", "account"));
            
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        JwtUtils.generateToken(keyPair.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER1,
                                               System.currentTimeMillis(),
                                               TEST_SUBJECT1, claims));
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            fail("Should be authorized");
        }
    }

    /**
     * Test authorizing with a valid token with a list of audiences in the token
     * and no list of accepted audiences set. Should not be authorized.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidTokenWithAudienceNoAccepted() throws Exception {
        LOG.info("testValidTokenWithAudienceNoAccepted");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
                    
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
            claims.put("aud", Arrays.asList("service1", "account"));
            
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        JwtUtils.generateToken(keyPair.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER1,
                                               System.currentTimeMillis(),
                                               TEST_SUBJECT1, claims));
            instance.isAuthorized(null, context);
            fail("Should have failed");
        } catch (AuthorizationRequiredException e) {
            assertEquals("Exception message",
                         "Authorization failed: Specific audience specified not among accepted: [service1, account]",
                         e.getMessage());
        }
    }

    /**
     * Test authorizing with a valid token with a list of audiences in the token
     * and a different list of accepted audiences. Should not be authorized.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidTokenWithAudienceOtherAccepted() throws Exception {
        LOG.info("testValidTokenWithAudienceOtherAccepted");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        config.setProperty("ACCEPTED_AUDIENCES", "service2, service3");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
                    
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
            claims.put("aud", Arrays.asList("service1", "account"));
            
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        JwtUtils.generateToken(keyPair.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER1,
                                               System.currentTimeMillis(),
                                               TEST_SUBJECT1,
                                               claims));
            instance.isAuthorized(null, context);
            fail("Should have failed");
        } catch (AuthorizationRequiredException e) {
            assertEquals("Exception message",
                         "Authorization failed: Specific audience specified not among accepted: [service1, account]",
                         e.getMessage());
        }
    }

    /**
     * Test authorizing with a valid token with no audience in the token
     * and a list of accepted audiences. Should be authorized.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidTokenWithNoAudienceSomeAccepted() throws Exception {
        LOG.info("testValidTokenWithNoAudienceSomeAccepted");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        config.setProperty("ACCEPTED_AUDIENCES", "service2, service3");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
                    
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
            
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        JwtUtils.generateToken(keyPair.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER1,
                                               System.currentTimeMillis(),
                                               TEST_SUBJECT1,
                                               claims));
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            fail("Should be authorized");
        }
    }

    /**
     * Test authorizing with a valid token with a single audiences in the token
     * and that audience in the list of accepted. Should be authorized.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidTokenWithSingleAudienceAccepted() throws Exception {
        LOG.info("testValidTokenWithNoAudienceSomeAccepted");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        config.setProperty("ACCEPTED_AUDIENCES", "service2, service3");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
                    
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
            claims.put("aud", "service2");
            
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        JwtUtils.generateToken(keyPair.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER1,
                                               System.currentTimeMillis(),
                                               TEST_SUBJECT1, claims));
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            fail("Should be authorized");
        }
    }
    
    /**
     * Test authorizing with a valid token.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidToken_ECDSA() throws Exception {
        LOG.info("testValidToken_ECDSA");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair3.getPublic().getEncoded())));
        config.setProperty("AUTHSERVER1.KEYALG", "ECDSA");
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        instance.init(42, config, null);
        System.err.println(instance.getFatalErrors());
        
        try {
            final RequestContext context = new RequestContext();
                    
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
        
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        JwtUtils.generateToken(keyPair3.getPrivate(),
                                               SignatureAlgorithm.ES256,
                                               TEST_ISSUER1,
                                               System.currentTimeMillis(),
                                               TEST_SUBJECT1, claims));
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            fail("Should be authorized");
        }
    }

    /**
     * Test authorizing with a valid token. Using a claim with a numeric value.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidTokenNumberInAuthRule() throws Exception {
        LOG.info("testValidTokenNumberInAuthRule");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "num");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "42");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
                    
            final Map<String, Object> claims = new HashMap<>();
            claims.put("num", 42);
        
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        JwtUtils.generateToken(keyPair.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER1,
                                               System.currentTimeMillis(),
                                               TEST_SUBJECT1, claims));
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            fail("Should be authorized");
        }
    }

    /**
     * Test authorizing with a valid token. With rules for different issuers.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidTokenAdditionalRule() throws Exception {
        LOG.info("testValidTokenAdditionalRule");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHSERVER2.ISSUER", TEST_ISSUER2);
        config.setProperty("AUTHSERVER2.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair2.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        config.setProperty("AUTHJWT38.ISSUER", TEST_ISSUER2);
        config.setProperty("AUTHJWT38.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT38.CLAIM.VALUE", "scope2");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
                    
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope2"));
        
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        JwtUtils.generateToken(keyPair2.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER2,
                                               System.currentTimeMillis(),
                                               TEST_SUBJECT1, claims));
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            fail("Should be authorized");
        }
    }

    /**
     * Test authorizing when auth rule does not match the token.
     * 
     * @throws Exception 
     */
    @Test
    public void testInvalidTokenNotMatchingRule() throws Exception {
        LOG.info("testInvalidTokenNotMatchingRule");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
                    
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope2"));
        
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER,
                        JwtUtils.generateToken(keyPair.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER1,
                                               System.currentTimeMillis(),
                                               TEST_SUBJECT1, claims));
            instance.isAuthorized(null, context);
            fail("Should have failed");
        } catch (AuthorizationRequiredException e) {
            assertEquals("Exception message", "Not authorized",
                         e.getMessage());
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
        LOG.info("testNoToken");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();

            instance.isAuthorized(null, context);
            fail("Should have failed");
        } catch (AuthorizationRequiredException e) {
            assertEquals("Exception message", "Authorization required",
                         e.getMessage());
        }
    }
    
    /**
     * Test authorizing with an unsigned token (algorithm NONE).
     * 
     * @throws Exception 
     */
    @Test
    public void testStrippedSignature() throws Exception {
        LOG.info("testStrippedSignature");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER4.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER4.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
                    
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
        
            final String token =
                    JwtUtils.generateToken(keyPair.getPrivate(),
                                           SignatureAlgorithm.RS256,
                                           TEST_ISSUER1,
                                           System.currentTimeMillis(),
                                           TEST_SUBJECT1, claims);
            
            final String[] parts = token.split("\\.");
            
            final String strippedToken = Base64.getEncoder().encodeToString(new String(Base64.getDecoder().decode(parts[0]), StandardCharsets.UTF_8).replace("RS256", "NONE").getBytes(StandardCharsets.UTF_8)) + "." + parts[1] + ".";
            
            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER, strippedToken);
            instance.isAuthorized(null, context);
            fail("Token unsigned");
        } catch (AuthorizationRequiredException e) {
            assertEquals("Exception message", "Authorization failed: Unsigned Claims JWTs are not supported.",
                         e.getMessage());
        }
    }
    
    /**
     * Test authorizing with a token that has got a change in its body after 
     * signing.
     *
     * @throws Exception 
     */
    @Test
    public void testManipulatedToken() throws Exception {
        LOG.info("testManipulatedToken");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER4.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER4.PUBLICKEY",
                           new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())));
        config.setProperty("AUTHJWT37.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHJWT37.CLAIM.NAME", "scopes");
        config.setProperty("AUTHJWT37.CLAIM.VALUE", "scope1");
        instance.init(42, config, null);
        
        try {
            final RequestContext context = new RequestContext();
                    
            final Map<String, Object> claims = new HashMap<>();
            claims.put("scopes", Arrays.asList("scope3", "scope4", "scope1"));
        
            final String token =
                    JwtUtils.generateToken(keyPair.getPrivate(),
                                           SignatureAlgorithm.RS256,
                                           TEST_ISSUER1,
                                           System.currentTimeMillis(),
                                           TEST_SUBJECT1, claims);
            
            final String[] parts = token.split("\\.");
            final String modifiedBody = Base64.getEncoder().encodeToString(new String(Base64.getDecoder().decode(parts[1]), StandardCharsets.UTF_8).replace("scope1", "scope2").getBytes(StandardCharsets.UTF_8));
            final String modifiedToken = parts[0] + "." + modifiedBody + "." + parts[2];

            context.put(RequestContext.CLIENT_CREDENTIAL_BEARER, modifiedToken);
            instance.isAuthorized(null, context);
            fail("Token unsigned");
        } catch (AuthorizationRequiredException e) {
            assertEquals("Exception message", "Authorization failed: JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.",
                         e.getMessage());
        }
    }

    /**
     * Test authorizing with a valid token for another issuer that is not 
     * trusted.
     * Should not be authorized.
     * 
     * @throws Exception 
     */
    @Test
    public void testValidTokenOtherIssuer() throws Exception {
        LOG.info("testValidTokenOtherIssuer");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER2);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
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
                        JwtUtils.generateToken(keyPair.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER1,
                                               System.currentTimeMillis(),
                                               TEST_SUBJECT1, claims));
            instance.isAuthorized(null, context);
            fail("Should have failed with unknown issuer");
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
        LOG.info("testValidTokenOtherPublicKey");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
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
                        JwtUtils.generateToken(keyPair2.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER2,
                                               System.currentTimeMillis(),
                                               TEST_SUBJECT1, claims));
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
        LOG.info("testValidTokenExpiredDefaultScew");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
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
                        JwtUtils.generateToken(keyPair.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER1, issuedAt,
                                               TEST_SUBJECT1, claims));
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
        LOG.info("testValidTokenWithinDefaultScew");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
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
                        JwtUtils.generateToken(keyPair.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER1, issuedAt,
                                               TEST_SUBJECT1, claims));
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
        LOG.info("testValidExpiredShortAllowedScew");

        final JwtAuthorizer instance = new JwtAuthorizer();
        final WorkerConfig config = new WorkerConfig();

        config.setProperty("AUTHSERVER1.ISSUER", TEST_ISSUER1);
        config.setProperty("AUTHSERVER1.PUBLICKEY",
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
                        JwtUtils.generateToken(keyPair.getPrivate(),
                                               SignatureAlgorithm.RS256,
                                               TEST_ISSUER1, issuedAt,
                                               TEST_SUBJECT1, claims));
            instance.isAuthorized(null, context);
        } catch (AuthorizationRequiredException e) {
            assertTrue("Exception message: " + e.getMessage(), e.getMessage().contains("Authorization failed"));
            assertTrue("Exception message: " + e.getMessage(), e.getMessage().contains("expired"));
        }
    }
}
