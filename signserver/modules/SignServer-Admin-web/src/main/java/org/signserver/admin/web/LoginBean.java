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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.RequestScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import org.apache.log4j.Logger;
import org.signserver.common.CompileTimeSettings;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ManagedBean
@RequestScoped
public class LoginBean {
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(LoginBean.class);
    
    private static final String HTTPSERVER_EXTERNAL_PRIVHTTPS = "httpserver.external.privhttps";
    
    private final CompileTimeSettings settings = CompileTimeSettings.getInstance();
    
    // XXX: Duplicated in index.jsp of public web (but using JSP)
    public String getAdminWebPrivateHttpsLink() {
        
        ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();
        String contextPath = externalContext.getRequestContextPath();

        try {
            final URL url =
                    new URL("https", externalContext.getRequestServerName(),
                            getExternalPrivateHttpsPort(), contextPath);

            return url.toExternalForm();
        } catch (MalformedURLException ex) {
            LOG.error("Malformed URL");
            throw new RuntimeException(ex);
        }
    }
    
    // XXX: Duplicated in SettingsBean of public web
    private int getExternalPrivateHttpsPort() {
        int value = 8443;
        try {
            value = Integer.parseInt(settings.getProperty(HTTPSERVER_EXTERNAL_PRIVHTTPS));
        } catch (NumberFormatException e) { // NOPMD
            LOG.warn("\"httpserver.external.privhttps\" is not a decimal number. Using default value: " + value);
        }
        return value;
    }
}
