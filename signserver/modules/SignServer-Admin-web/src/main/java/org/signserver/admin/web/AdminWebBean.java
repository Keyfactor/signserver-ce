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

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.Properties;

import jakarta.annotation.ManagedBean;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.faces.context.FacesContext;
import jakarta.inject.Named;
import org.apache.commons.lang.time.FastDateFormat;
import org.cesecore.config.CesecoreConfiguration;
import org.signserver.common.CompileTimeSettings;
import org.signserver.web.common.ThemeHelper;

/**
 * Managed beam providing static information to the templates.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ApplicationScoped
@Named
public class AdminWebBean implements Serializable {

    private static final FastDateFormat FDF = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZ");

    private final Properties docLinks = new Properties();

    @PostConstruct
    protected void init() {
        // Load the documentation links map
        InputStream in = getClass().getResourceAsStream("/doc-links.properties");
        if (in == null) {
            throw new IllegalStateException("Resource /doc-links.properties not available");
        }
        try {
            docLinks.load(in);
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to load /doc-links.properties: " + ex.getMessage(), ex);
        }
    }

    public String getProductName() {
        return CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.APPNAME_CAP);
    }

    public String getProductVersion() {
        return CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_VERSION_NUMBER);
    }

    public String getVersion() {
        return CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_VERSION);
    }

    public String getEdition() {
        return CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_EDITION);
    }

    public String getCopyright() {
        return "Copyright © 2006–2025 Keyfactor";
    }

    public String getCurrentTime() {
        return FDF.format(System.currentTimeMillis());
    }

    public String getNode() {
        return CesecoreConfiguration.getNodeIdentifier();
    }

    public String getTheme() {
        return ThemeHelper.getInstance().getTheme();
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
        String subPage = getDocumentationLink(FacesContext.getCurrentInstance().getViewRoot().getViewId());
        if (subPage == null) {
            subPage = "";
        }
        return "../doc/" + subPage;
    }

    /**
     * Get the documentation link for a given page without any path if it
     * exists.
     *
     * @param viewId Page to get the documentation link for
     * @return The link or null if no link exists
     */
    protected String getDocumentationLink(final String viewId) {
        return docLinks.getProperty(viewId);
    }
}
