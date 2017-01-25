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
package org.signserver.common;

import java.io.Serializable;
import java.util.Enumeration;
import java.util.Properties;

import org.apache.log4j.Logger;

/**
 * Value object containing the global configuration, both global and
 * node scoped.
 *
 * Contains a merge of static and dynamically defined global properties
 *
 * @author Philip Vendil
 * @version $Id$
 */
public class GlobalConfiguration implements Serializable {

    private static final long serialVersionUID = 1L;
    
    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(GlobalConfiguration.class);
    
    public static final String SCOPE_GLOBAL = "GLOB.";
    public static final String SCOPE_NODE = "NODE.";
    public static final String STATE_INSYNC = "INSYNC";
    public static final String STATE_OUTOFSYNC = "OUTOFSYNC";
    public static final String WORKERPROPERTY_BASE = "WORKER";
    public static final String WORKERPROPERTY_CLASSPATH = ".CLASSPATH";

    private final Properties config;
    private final String state;
    private final String appVersion;

    /**
     * Constructor that should only be called within
     * the GlobalConfigurationSessionBean.
     * 
     * @param config
     * @param state
     * @param appVersion
     */
    public GlobalConfiguration(Properties config, String state, String appVersion) {
        this.config = config;
        this.state = state;
        this.appVersion = appVersion;
    }

    /**
     * Returns the currently set global property.
     * @param scope one of the SCOPE_ constants
     * @param property the actual property (with no glob. or node. prefixes)
     * @return the currently set global property or null if it doesn't exist.
     */
    public String getProperty(String scope, String property) {
        return (String) config.getProperty((scope + property).toUpperCase());
    }

    /**
     * Returns the currently set global property with a scoped property.
     *
     * Use this method only if you know what you are doing.
     *
     * @param propertyWithScope the actual property (with  GLOB. or NODE. prefixes)
     * @return the currently set global property or null if it doesn't exist.
     */
    public String getProperty(String propertyWithScope) {
        return (String) config.getProperty(propertyWithScope);
    }

    /**
     * @return Returns an iterator to all configured properties
     */
    @SuppressWarnings("unchecked")
    public Enumeration<String> getKeyEnumeration() {
        return (Enumeration<String>) config.propertyNames();
    }

    /**
     * @return Returns the current state of the global configuration
     * one of the STATE_ constants.
     */
    public String getState() {
        return state;
    }

    /**
     * @return the version of the server
     */
    public String getAppVersion() {
        return appVersion;
    }

    /**
     * @return A new Properties object with the current configuration
     */
    public Properties getConfig() {
        Properties properties = new Properties();
        properties.putAll(config);
        return properties;
    }
    
}
