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
package org.signserver.adminws;

import java.util.Properties;
import org.signserver.common.GlobalConfiguration;

/**
 * Class holding the global configuration.
 * @see GlobalConfiguration
 * @author Markus Kilås
 * @version $Id$
 */
public class WSGlobalConfiguration {

    /** serialVersionUID for this class. */
    private static final long serialVersionUID = 1;

    private Properties config;
    private String state;

    private String appVersion;
    private boolean clusterClassLoaderEnabled;
    private boolean useClassVersions;
    private boolean requireSigning;

    public WSGlobalConfiguration() {
    }

    public String getAppVersion() {
        return appVersion;
    }

    public void setAppVersion(String appVersion) {
        this.appVersion = appVersion;
    }

    public boolean isClusterClassLoaderEnabled() {
        return clusterClassLoaderEnabled;
    }

    public void setClusterClassLoaderEnabled(boolean clusterClassLoaderEnabled) {
        this.clusterClassLoaderEnabled = clusterClassLoaderEnabled;
    }

    public Properties getConfig() {
        return config;
    }

    public void setConfig(Properties config) {
        this.config = config;
    }

    public boolean isRequireSigning() {
        return requireSigning;
    }

    public void setRequireSigning(boolean requireSigning) {
        this.requireSigning = requireSigning;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public boolean isUseClassVersions() {
        return useClassVersions;
    }

    public void setUseClassVersions(boolean useClassVersions) {
        this.useClassVersions = useClassVersions;
    }
    
}
