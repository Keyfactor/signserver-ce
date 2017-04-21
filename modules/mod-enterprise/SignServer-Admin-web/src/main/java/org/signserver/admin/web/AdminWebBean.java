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
import java.util.Properties;
import javax.annotation.PostConstruct;
import javax.faces.bean.ApplicationScoped;
import javax.faces.bean.ManagedBean;
import javax.faces.context.FacesContext;
import org.apache.commons.lang.time.FastDateFormat;
import org.cesecore.config.CesecoreConfiguration;
import org.signserver.common.CompileTimeSettings;

/**
 *
 * @author Markus Kilås
 * @version $Id$
 */
@ApplicationScoped
@ManagedBean
public class AdminWebBean {

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
    
    public String getVersion() {
        return CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_VERSION);
    }

    public String getCopyright() {
        return "Copyright © 2006–2017 PrimeKey Solutions AB";
    }

    public String getCurrentTime() {
        return FDF.format(System.currentTimeMillis());
    }
    
    public String getNode() {
        return CesecoreConfiguration.getNodeIdentifier();
    }

    /**
     * @return The link to the documentation most relevant for the current page.
     */
    public String getDocumentationLink() {
        final String viewId = FacesContext.getCurrentInstance().getViewRoot().getViewId();
        return "../doc/" + docLinks.getProperty(viewId, "");
    }
}
