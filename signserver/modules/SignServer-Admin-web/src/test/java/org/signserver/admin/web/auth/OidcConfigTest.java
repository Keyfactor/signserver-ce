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

import org.apache.log4j.Logger;
import org.junit.Test;
import org.signserver.admin.common.config.OidcConfig;

import java.lang.reflect.Method;

import static org.junit.Assert.assertEquals;

public class OidcConfigTest {
    private static final Logger LOG = Logger.getLogger(OidcConfigTest.class);

    /**
     * Verifies that OidcConfig initializes from a classpath properties file
     * and that loaded values match expectations.
     */
    @Test
    public void testLoadingOidcPropertiesAndValues() throws Exception {
        LOG.info("testLoadingOidcPropertiesAndValues");
        OidcConfig cfg = new OidcConfig();

        Method init = OidcConfig.class.getDeclaredMethod("init");
        init.setAccessible(true);
        init.invoke(cfg);

        // Verify values loaded from src/test/resources/oidc.properties
        assertEquals("test-client-id", cfg.getClientId());
        assertEquals("test-secret", cfg.getClientSecret());
        assertEquals("https://provider.example", cfg.getProviderUri());
        assertEquals("https://app.example/signserver", cfg.getLogoutUri());
        assertEquals("https://app.example/signserver/adminweb/workers.xhtml", cfg.getRedirectUri());
        assertEquals("https://app.example/signserver/adminweb/callback", cfg.getLoginUri());
        assertEquals("https://provider.example/v2/logout", cfg.getProviderLogOutUri());
        assertEquals("kf.roles", cfg.getCallerGroupsClaim());
        assertEquals("test-client-id", cfg.getAudience());

        // Callback should be initialized to the login URI
        assertEquals(cfg.getLoginUri(), cfg.getCallbackUri());
        // Client ID and the audience should be the same
        assertEquals(cfg.getClientId(), cfg.getAudience());
    }
}
