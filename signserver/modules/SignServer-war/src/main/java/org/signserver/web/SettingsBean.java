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

import org.signserver.common.CompileTimeSettings;

/**
 * Bean exposing settings to the JSP pages.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SettingsBean {
    
    /** Key in signservercompile.properties. */
    private static final String WEBDOC_ENABLED = "webdoc.enabled";
    
    private CompileTimeSettings settings = CompileTimeSettings.getInstance();
    
    /**
     * @return If the web documentation is enabled. 
     */
    public boolean isWebDocEnabled() {
        final String enabled = settings.getProperty(WEBDOC_ENABLED);
        return enabled != null && Boolean.parseBoolean(enabled);
    }
}
