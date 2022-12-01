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
package org.signserver.web;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;
import org.signserver.common.CompileTimeSettings;
import org.signserver.web.common.ThemeHelper;

import javax.faces.bean.ApplicationScoped;
import javax.faces.bean.ManagedBean;
import javax.inject.Named;

/**
 * JSF managed bean exposing settings to the JSF pages.
 *
 * @author Vinay Singh
 * @version $Id$
 *
 */
@Named("publicWebBean")
@ApplicationScoped
@ManagedBean
public class PublicWebBean {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(PublicWebBean.class);

    /** Key in signservercompile.properties. */
    private static final String ADMINWEB_ENABLED_AND_AVAILABLE = "adminweb.enabled.available";
    private static final String WEBDOC_ENABLED = "webdoc.enabled";
    private static final String WEB_ADMINGUI_DIST_ENABLED = "web.admingui.dist.enabled";
    private static final String WEB_ADMINGUI_DIST_FILE = "web.admingui.dist.file";
    private static final String WEB_CLIENTCLI_DIST_ENABLED = "web.clientcli.dist.enabled";
    private static final String WEB_CLIENTCLI_DIST_FILE = "web.clientcli.dist.file";
    private static final String HTTPSERVER_EXTERNAL_PRIVHTTPS = "httpserver.external.privhttps";

    private final CompileTimeSettings settings = CompileTimeSettings.getInstance();

    public PublicWebBean() {
    }

    /**
     * @return If the web documentation is enabled.
     */
    public boolean isAdminWebEnabledAndAvailable() {
        final String enabled = settings.getProperty(ADMINWEB_ENABLED_AND_AVAILABLE);
        return Boolean.parseBoolean(enabled);
    }

    /**
     * @return If the web documentation is enabled.
     */
    public boolean isWebDocEnabled() {
        final String enabled = settings.getProperty(WEBDOC_ENABLED);
        return Boolean.parseBoolean(enabled);
    }

    public boolean isWebAdminGUIDistEnabled() {
        final String enabled = settings.getProperty(WEB_ADMINGUI_DIST_ENABLED);
        return Boolean.parseBoolean(enabled);
    }

    public boolean isWebClientCLIDistEnabled() {
        final String enabled = settings.getProperty(WEB_CLIENTCLI_DIST_ENABLED);
        return Boolean.parseBoolean(enabled);
    }

    public File getAdminGUIDistFile() {
        final String fileName = settings.getProperty(WEB_ADMINGUI_DIST_FILE);
        if (LOG.isDebugEnabled()) {
            LOG.debug("AdminGUI dist file: " + fileName);
        }
        return fileName == null ? null : new File(fileName);
    }

    public File getClientCLIDistFile() {
        final String fileName = settings.getProperty(WEB_CLIENTCLI_DIST_FILE);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Client CLI dist file: " + fileName);
        }
        return fileName == null ? null : new File(fileName);
    }

    public boolean isWebAdminGUIDistAvailable() {
        final boolean result;
        if (!isWebAdminGUIDistEnabled()) {
            result = false;
        } else {
            final File file = getAdminGUIDistFile();
            if (file == null) {
                result = false;
            } else {
                result = file.exists() && file.isFile();
            }
        }
        return result;
    }

    public boolean isWebClientCLIDistAvailable() {
        final boolean result;
        if (!isWebClientCLIDistEnabled()) {
            result = false;
        } else {
            final File file = getClientCLIDistFile();
            if (file == null) {
                result = false;
            } else {
                result = file.exists() && file.isFile();
            }
        }
        return result;
    }

    public String getWebAdminGUIDistSize() {
        return String.format("%.2f MB", getAdminGUIDistFile().length() / 1000000f);
    }

    public String getWebClientCLIDistSize() {
        return String.format("%.2f MB", getClientCLIDistFile().length() / 1000000f);
    }

    /**
     * Port used by SignServer public web to construct a correct URL.
     * @return The port number
     */
    public int getExternalPrivateHttpsPort() {
        int value = 8443;
        try {
            value = Integer.parseInt(settings.getProperty(HTTPSERVER_EXTERNAL_PRIVHTTPS));
        } catch (NumberFormatException e) { // NOPMD
            LOG.warn("\"httpserver.external.privhttps\" is not a decimal number. Using default value: " + value);
        }
        return value;
    }

    public String getAdminWebPrivateHttpsLink() {

        ExternalContext externalContext = FacesContext.getCurrentInstance().getExternalContext();
        String contextPath = externalContext.getRequestContextPath();
        String adminWebContextPath = contextPath.concat("/adminweb/");

        try {
            final URL url =
                    new URL("https", externalContext.getRequestServerName(),
                            getExternalPrivateHttpsPort(), adminWebContextPath);

            return url.toExternalForm();
        } catch (MalformedURLException ex) {
            LOG.error("Malformed URL");
            throw new RuntimeException(ex);
        }
    }

    /**
     * Get the most relevant documentation link for the current page or use the
     * main page if no mapping exists.
     *
     * The path is prefix with the location of the documentation.
     *
     * @return The link to the documentation
     */
    public String getDocumentationLink() {
        return "../doc/";
    }

    public String getCopyright() {
        return "Copyright © 2006–2022 Keyfactor";
    }

    public String getNode() {
        return CesecoreConfiguration.getNodeIdentifier();
    }

    public String getEdition() {
        return CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_EDITION);
    }

    public String getTheme() {
        return ThemeHelper.getInstance().getTheme();
    }

    public String getProductName() {
        return CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.APPNAME_CAP);
    }

    public String getProductVersion() {
        return CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_EDITION)
                + " "
                + CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_VERSION_NUMBER);
    }

}
