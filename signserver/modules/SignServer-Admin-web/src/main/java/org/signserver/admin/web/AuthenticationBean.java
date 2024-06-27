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

import jakarta.annotation.ManagedBean;
import jakarta.faces.context.FacesContext;
import jakarta.faces.view.ViewScoped;
import jakarta.inject.Named;
import jakarta.servlet.http.HttpServletRequest;
import org.signserver.admin.web.ejb.NotLoggedInException;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import org.cesecore.util.CertTools;

/**
 * Responsible for extracting the certificate.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@Named
@ViewScoped
public class AuthenticationBean implements Serializable {

    private X509Certificate adminCertificate;

    /**
     * Creates a new instance of AuthenticationBean
     */
    public AuthenticationBean() {
    }

    private HttpServletRequest getHttpServletRequest() {
        return (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
    }

    public X509Certificate getAdminCertificate() throws NotLoggedInException {
        if (adminCertificate == null) {
            final X509Certificate[] certificates = (X509Certificate[]) getHttpServletRequest().getAttribute("jakarta.servlet.request.X509Certificate");
            if (certificates != null && certificates.length != 0) {
                adminCertificate = certificates[0];
            }
            if (adminCertificate == null) {
                throw new NotLoggedInException("Client certificate authentication required");
            }
        }
        return adminCertificate;
    }

    public String getUserDisplayName() throws NotLoggedInException {
        final String result;
        final X509Certificate cert = getAdminCertificate();
        if (cert == null) {
            result = "n/a";
        } else {
            String cn = CertTools.getPartFromDN(cert.getSubjectX500Principal().getName(), "CN");
            if (cn == null || cn.isEmpty()) {
                result = cert.getSerialNumber().toString(16);
            } else {
                result = cn;
            }
        }
        return result;

    }

    public boolean isCertificatePresent() {
        boolean result = false;
        try {
            result = getAdminCertificate() != null;
        } catch (NotLoggedInException ignored) { // NOPMD
        }
        return result;
    }

}
