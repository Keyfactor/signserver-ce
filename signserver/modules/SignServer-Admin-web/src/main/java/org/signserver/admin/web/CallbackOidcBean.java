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

package org.signserver.admin.web;

import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.SecurityContext;
import jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import jakarta.security.enterprise.authentication.mechanism.http.OpenIdAuthenticationMechanismDefinition;
import jakarta.security.enterprise.authentication.mechanism.http.openid.ClaimsDefinition;
import jakarta.security.enterprise.identitystore.openid.OpenIdContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.signserver.admin.common.config.OidcConfig;
import org.signserver.admin.web.auth.LoginFilter;
import org.signserver.admin.web.auth.LoginType;
import org.signserver.admin.web.auth.OidcAuthBean;

import java.io.IOException;

/**
 * Servlet for triggering OIDC flows and handle the callbacks.
 */
@OpenIdAuthenticationMechanismDefinition(
        clientId = "${oidcConfig.clientId}",
        clientSecret = "${oidcConfig.clientSecret}",
        redirectURI = "${oidcConfig.callbackUri}",
        providerURI = "${oidcConfig.providerUri}",
        jwksConnectTimeout = 5000,
        jwksReadTimeout = 5000,
        claimsDefinition = @ClaimsDefinition(callerGroupsClaim = "${oidcConfig.callerGroupsClaim}")
)
public class CallbackOidcBean implements CallbackInterface {
    private static final Logger LOG = Logger.getLogger(CallbackOidcBean.class);

    @Inject
    private SecurityContext securityContext;

    @Inject
    private OpenIdContext context;

    @Inject
    OidcConfig oidcConfig;

    @Inject
    OidcAuthBean oidcAuthBean;
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final LoginType loginType = (LoginType) request.getSession().getAttribute(LoginFilter.LOGGEDIN_ATTRIBUTE);
        if (loginType == null) {
            // Programatically trigger login, as we do not want to specify @HttpContraint(rolesAllowed=...)
            AuthenticationStatus status = null;
            try {
                status = securityContext.authenticate(request, response, new AuthenticationParameters());
            } catch (IllegalStateException ex) {
                LOG.error("OIDC properties misconfigured: ", ex);
                // We assume oidc.properties has been misconfigured, so we redirect to login.xhtml with query parameter
                // containing relevant error code.
                response.sendRedirect(request.getContextPath() + "/login.xhtml?error=1");
            } catch (Exception ex) {
                LOG.error("OIDC authentication failed: ", ex);
                // We assume OIDC authentication failed, so we redirect to login.xhtml with query parameter
                // containing relevant error code.
                response.sendRedirect(request.getContextPath() + "/login.xhtml?error=2");
                return;
            }

            if (oidcAuthBean.isOidcAuthenticated() && !oidcAuthBean.isAudienceValidOrNotUsed()) {
                LOG.error("The audience value is defined in the oidc.properties file. During authentication, SignServer checks that this value matches the audience provided by the Identity Provider." +
                        " If they do not match, authentication fails due to an invalid audience.");
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Expected audience: " + oidcConfig.getAudience() + " Received audience from the Identity Provider: "
                            + context.getIdentityToken().getJwtClaims().getAudience());
                }
                // We assume the Audience in the IdentityToken does not match with the audience value set in the oidc properties file
                // so we redirect to login.xhtml with query parameter
                // containing relevant error code.
                response.sendRedirect(request.getContextPath() + "/login.xhtml?error=3");
            } else if (status == AuthenticationStatus.SUCCESS && oidcAuthBean.isAudienceValidOrNotUsed()) {
                LOG.info("OIDC callback success. Redirecting to: " + oidcConfig.getRedirectUri());
                response.sendRedirect(oidcConfig.getRedirectUri());
            }
        } else {
            response.sendRedirect(request.getContextPath() + "/login.xhtml");
        }
    }

}
