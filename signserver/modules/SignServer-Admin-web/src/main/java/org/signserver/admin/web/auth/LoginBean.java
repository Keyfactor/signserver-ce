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

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Named;
import jakarta.faces.context.FacesContext;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.Serializable;
import org.signserver.admin.common.auth.AdminPrincipal;
import org.signserver.admin.common.roles.AdminsUtil;

import static org.signserver.admin.web.auth.LoginFilter.LOGGEDIN_ATTRIBUTE;

/**
 * Bean responsible for managing the login "consent" state.
 *
 * A user is considered logged in if and only if the session has the LOGGEDIN
 * attribute set to true and the user is authenticated (i.e. by client-cert or
 * possible future other methods).
 */
@Named(value = "loginBean")
@RequestScoped
public class LoginBean implements Serializable {

    @Inject
    private ClientCertAuthBean clientCertAuth;

    @Inject
    private OidcAuth oidcAuth;

    private String errorCode;

    /**
     * Creates a new instance of LoginBean
     */
    public LoginBean() {
    }

    public String validateLogin(boolean clientCert) {
        String page = "login.xhtml?faces-redirect=true&amp;includeViewParams=true";
        if (clientCert) {
            if (isClientCertificateAuthenticated()) {
                // TODO: In the future could also call WorkerSession or similar there to have the login really validated + audit logged
                HttpSession session = (HttpSession) FacesContext.getCurrentInstance().getExternalContext().getSession(false);
                session.setAttribute(LOGGEDIN_ATTRIBUTE, LoginType.CLIENT_CERT);
                page = "workers.xhtml?faces-redirect=true&amp;includeViewParams=true";
            }
        } else {
            if (isOidcAuthenticated()) {
                if (isAudienceValidOrNotUsed()) {
                    // TODO: In the future could also call WorkerSession or similar there to have the login really validated + audit logged
                    HttpSession session = (HttpSession) FacesContext.getCurrentInstance().getExternalContext().getSession(false);
                    session.setAttribute(LOGGEDIN_ATTRIBUTE, LoginType.OIDC);
                    page = "workers.xhtml?faces-redirect=true&amp;includeViewParams=true";
                } else {
                    page = "login.xhtml?faces-redirect=true&amp;includeViewParams=true&amp;error=3";
                }
            }
        }
        return page;
    }
    
    public boolean isLoggedIn() {
        HttpSession session = (HttpSession) FacesContext.getCurrentInstance().getExternalContext().getSession(false);
        return session != null && session.getAttribute(LOGGEDIN_ATTRIBUTE) != null;
    }
    
    public LoginType getLoginType() {
        HttpSession session = (HttpSession) FacesContext.getCurrentInstance().getExternalContext().getSession(false);
        return (LoginType) session.getAttribute(LOGGEDIN_ATTRIBUTE);
    }

    public String logout() throws IOException {
        HttpSession session = (HttpSession) FacesContext.getCurrentInstance().getExternalContext().getSession(false);
        session.removeAttribute(LOGGEDIN_ATTRIBUTE);
        session.invalidate();
        // TODO: In the future could also call WorkerSession or similar there to have the logout really validated + audit logged

        // Also logout identity provider
        if (isOidcAuthenticated()) {
            FacesContext.getCurrentInstance().getExternalContext().redirect(oidcAuth.getOidcLogoutRedirect());
            return "login.xhtml";
        }

        return "login.xhtml?faces-redirect=true&amp;includeViewParams=true";
    }

    public ClientCert getClientCert() {
        return clientCertAuth.getClientCert();
    }
    
    public boolean isClientCertificateAuthenticated() {
        return clientCertAuth.isClientCertificateAuthenticated();
    }

    public boolean isOidcAuthenticated() {
        return oidcAuth.isOidcAuthenticated();
    }

    public boolean isAudienceValidOrNotUsed() {
        return oidcAuth.isAudienceValidOrNotUsed();
    }

    public OidcTokens getClientTokens() {
        return oidcAuth.getClientTokens();
    }

    public String getOidcLoginLink() {
        return oidcAuth.getOidcLoginLink();
    }

    public String getOidcProviderUri() {
        return oidcAuth.getOidcProviderUri();
    }

    public String getProviderLogoutUri() {
        return oidcAuth.getOidcProviderLogoutUri();
    }

    public boolean isLoginTypeClientCert() {
        return getLoginType() == LoginType.CLIENT_CERT;
    }

    public boolean isLoginTypeOIDC() {
        return getLoginType() == LoginType.OIDC;
    }

    public String getRolesString() {
        return AdminsUtil.getRolesString(getAdminPrincipal().getRoles());
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorMessage) {
        this.errorCode = errorMessage;
    }

    public String errorDisplayMessage() {
        switch (errorCode) {
            case "1":
                return "OIDC is misconfigured. Check the application logs for details.";
            case "2":
                return "OIDC authentication failed. This could be temporarily failure or a configuration error. Check the application logs for details.";
            case "3":
                return "Audience is not valid. Check the application logs for details.";
            default:
                return "Something went wrong. Check the application logs for details.";
        }
    }

    public AdminPrincipal getAdminPrincipal() {
        final AdminPrincipal result;
        switch (getLoginType()) {
            case OIDC:
                result = oidcAuth.getAdminPrincipal();
                break;
            case CLIENT_CERT:
                result = clientCertAuth.getAdminPrincipal();
                break;
            default:
                result = null;
        }
        return result;
    }
}
