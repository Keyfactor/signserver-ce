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
package org.signserver.admin.common.config;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;
import java.io.IOException;
import java.io.InputStream;
import org.apache.log4j.Logger;

import java.util.Properties;

/**
 * Bean managing OIDC configuration.
 */
@ApplicationScoped
@Named("oidcConfig")
public class OidcConfig {

    private static final Logger LOG = Logger.getLogger(OidcConfig.class);

    private String clientId;
    private String clientSecret;
    private String providerUri;
    private String logoutUri;
    private String redirectUri;
    private String loginUri;
    private String callbackUri;
    private String providerLogOutUri;
    private String callerGroupsClaim;
    private String audience;

    @PostConstruct
    void init() {
        final Properties properties = new Properties();
        InputStream in = null;
        try {
            in = OidcConfig.class.getResourceAsStream("/oidc.properties");
            if (in != null) {
                properties.load(in);
                clientId = properties.getProperty("oidc.clientId");
                clientSecret = properties.getProperty("oidc.clientSecret");
                providerUri = properties.getProperty("oidc.providerUri");
                logoutUri = properties.getProperty("oidc.logoutUri");
                redirectUri = properties.getProperty("oidc.redirectUri");
                loginUri = properties.getProperty("oidc.loginUri");
                providerLogOutUri = properties.getProperty("oidc.providerLogOutUri");
                callerGroupsClaim = properties.getProperty("oidc.callerGroupsClaim");
                audience = properties.getProperty("oidc.audience");
                callbackUri = loginUri;
            }
        } catch (IOException ex) {
            LOG.error("Could not load configuration: " + ex.getMessage());
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOG.error("Failed to close configuration", ex);
                }
            }
        }
    }

    public String getClientId() {
        return clientId;
    }

    public String getLogoutUri() {
        return logoutUri;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getProviderUri() {
        return providerUri;
    }

    public void setProviderUri(String providerUri) {
        this.providerUri = providerUri;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getLoginUri() {
        return loginUri;
    }

    public void setLoginUri(String loginUri) {
        this.loginUri = loginUri;
    }

    public String getCallbackUri() {
        return callbackUri;
    }

    public void setCallbackUri(String callbackUri) {
        this.callbackUri = callbackUri;
    }

    public String getProviderLogOutUri() {
        return providerLogOutUri;
    }

    public void setProviderLogOutUri(String providerLogOutUri) {
        this.providerLogOutUri = providerLogOutUri;
    }

    public String getCallerGroupsClaim() {
        return callerGroupsClaim;
    }

    public void setCallerGroupsClaim(String callerGroupsClaim) {
        this.callerGroupsClaim = callerGroupsClaim;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }
}
