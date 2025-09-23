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
package org.signserver.admin.web.auth;

/**
 * Unit tests for the OidcAuthBean class.
 */

import jakarta.inject.Inject;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import org.signserver.admin.common.config.OidcConfig;

import java.security.Security;
import java.util.Map;
import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.*;

public class OidcAuthBeanUnitTest {
    private static final Logger LOG = Logger.getLogger(OidcAuthBeanUnitTest.class);
    private static final String AUDIANCE_OK = "TEST_AUDIANCE_OK";
    private static final String AUDIANCE_NOT_OK = "AUDIANCE_NOT_OK";

    @Inject
    private OidcAuthBean oidcAuth;

    @BeforeClass
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Tests that isAudienceValidOrNotUsed returns true when audiences set in OidcConfig and IdentityToken are match.
     */
    @Test
    public void testAudience_OK() throws Exception {
        LOG.info("testAudience_OK");
        OidcAuthBean oidcAuthBean = new OidcAuthBean();

        // Create Mock OidcConfig and set in OidcAuthBean
        OidcConfig oidcConfig = new OidcConfig();
        oidcConfig.setAudience(AUDIANCE_OK);
        oidcAuthBean.setOidcConfig(oidcConfig);

        // Create claimsMap to use in IdentityToken
        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("aud", List.of(AUDIANCE_OK));
        MockJwtClaims mockJwtClaims = new MockJwtClaims(claimsMap);

        // Create IdentityToken and set cliamsMpa and JwtClaims in it
        MockIdentityToken mockIdentityToken = new MockIdentityToken("", mockJwtClaims, false, claimsMap);

        // Create OpenIdContext and set IdentityToken in it
        MockOpenIdContext mockOpenIdContext = new MockOpenIdContext(mockIdentityToken);

        // Set mock OpenIdContext in to OidcAuthBean
        oidcAuthBean.setContext(mockOpenIdContext);

        assertTrue("Audience match in oidc Config and Identity token: ", oidcAuthBean.isAudienceValidOrNotUsed());
    }

    /**
     * Tests that isAudienceValidOrNotUsed returns false when audiences set in OidcConfig and IdentityToken are not match.
     */
    @Test
    public void testAudience_Fail() throws Exception {
        LOG.info("testAudience_Fail");
        OidcAuthBean oidcAuthBean = new OidcAuthBean();

        // Create Mock OidcConfig and set in OidcAuthBean
        OidcConfig oidcConfig = new OidcConfig();
        oidcConfig.setAudience(AUDIANCE_NOT_OK);
        oidcAuthBean.setOidcConfig(oidcConfig);

        // Create claimsMap to use in IdentityToken
        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("aud", List.of(AUDIANCE_OK));
        MockJwtClaims mockJwtClaims = new MockJwtClaims(claimsMap);

        // Create IdentityToken and set cliamsMpa and JwtClaims in it
        MockIdentityToken mockIdentityToken = new MockIdentityToken("", mockJwtClaims, false, claimsMap);

        // Create OpenIdContext and set IdentityToken in it
        MockOpenIdContext mockOpenIdContext = new MockOpenIdContext(mockIdentityToken);

        // Set mock OpenIdContext in to OidcAuthBean
        oidcAuthBean.setContext(mockOpenIdContext);

        assertFalse("Audience not match in oidc Config and Identity token: ", oidcAuthBean.isAudienceValidOrNotUsed());
    }
}
