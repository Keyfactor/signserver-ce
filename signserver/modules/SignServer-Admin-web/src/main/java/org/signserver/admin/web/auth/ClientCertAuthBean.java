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

import jakarta.annotation.PostConstruct;
import jakarta.ejb.EJB;
import jakarta.enterprise.context.RequestScoped;
import jakarta.faces.context.FacesContext;
import jakarta.inject.Named;
import jakarta.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import org.signserver.admin.common.auth.AdminAuthHelper;
import org.signserver.admin.common.auth.AdminPrincipal;
import org.signserver.admin.common.auth.ClientCertAdminPrincipal;
import org.signserver.admin.web.ejb.NotLoggedInException;
import org.signserver.ejb.interfaces.GlobalConfigurationSessionLocal;

/**
 * Supports getting client certificate.
 */
@Named(value = "clientCertAuthBean")
@RequestScoped
public class ClientCertAuthBean {
    
    private ClientCert clientCert;
    
    private AdminAuthHelper helper;
    
    @EJB
    private GlobalConfigurationSessionLocal globalConfig;

    public ClientCertAuthBean() {
    }

    @PostConstruct
    public void init() {
        helper = new AdminAuthHelper(globalConfig);
    }

    public ClientCert getClientCert() {
        if (clientCert == null) {
            clientCert = new ClientCert(getX509Certificate());
        }
        return clientCert;
    }
    
    public boolean isClientCertificateAuthenticated() {
        return getX509Certificate() != null;
    }

    private HttpServletRequest getHttpServletRequest() {
        return (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
    }

    private X509Certificate getX509Certificate() {
        X509Certificate result = null;
        final X509Certificate[] certificates = (X509Certificate[]) getHttpServletRequest().getAttribute("jakarta.servlet.request.X509Certificate");
        if (certificates != null && certificates.length != 0) {
            result = certificates[0];
        }
        return result;
    }

    public AdminPrincipal getAdminPrincipal() {
        X509Certificate cert = getX509Certificate();
        return new ClientCertAdminPrincipal(cert, helper.getRoles(cert));
    }

}
