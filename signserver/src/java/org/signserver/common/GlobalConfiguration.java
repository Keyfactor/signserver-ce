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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
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
 * $Id$
 */
public class GlobalConfiguration implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final Logger LOG = Logger.getLogger(GlobalConfiguration.class);

    /** Properties put together at compile-time. */
    private static final Properties COMPILETIME_PROPERTIES = new Properties();

    /** Default values for the compile-time properties. */
    private static final Properties DEFAULT_PROPERTIES = new Properties();

    public static final String SCOPE_GLOBAL = "GLOB.";
    public static final String SCOPE_NODE = "NODE.";
    public static final String STATE_INSYNC = "INSYNC";
    public static final String STATE_OUTOFSYNC = "OUTOFSYNC";
    public static final int WORKERTYPE_ALL = 1;
    public static final int WORKERTYPE_PROCESSABLE = 2;
    public static final int WORKERTYPE_SERVICES = 3;
    public static final int WORKERTYPE_MAILSIGNERS = 4;
    public static final String WORKERPROPERTY_BASE = "WORKER";
    public static final String WORKERPROPERTY_CLASSPATH = ".CLASSPATH";
    public static final String CRYPTOTOKENPROPERTY_BASE = ".CRYPTOTOKEN";
    public static final String OLD_CRYPTOTOKENPROPERTY_BASE = ".SIGNERTOKEN";
    public static final String CRYPTOTOKENPROPERTY_CLASSPATH = ".CLASSPATH";

    private static final String PROPERTY_APPNAME
            = "appname";
    private static final String PROPERTY_APPNAME_CAP
            = "appname_capital";
    private static final String PROPERTY_RMIREGISTRYPORT
            = "rmiregistryport";
    private static final String PROPERTY_RMISERVERPORT
            = "rmiserverport";
    private static final String PROPERTY_MAILSIGNERPORT
            = "mailsignerport";
    private static final String PROPERTY_BUILDMODE
            = "buildmode";
    private static final String PROPERTY_DATASOURCE_JNDINAMEPREFIX
            = "datasource.jndi-name-prefix";
    private static final String PROPERTY_DATASOURCE_JNDINAME
            = "datasource.jndi-name";
    private static final String PROPERTY_HEALTHECK_AUTHORZEDIPS
            = "healthcheck.authorizedips";
    private static final String PROPERTY_HEALTHECK_MINIMUMFREEMEMORY
            = "healthcheck.minimumfreememory";
    private static final String PROPERTY_HEALTHECK_CHECKDBSTRING
            = "healthcheck.checkdbstring";
    private static final String PROPERTY_SIGNSERVER_USECLUSTERCLASSLOADER
            = "signserver.useclusterclassloader";
    private static final String PROPERTY_SIGNSERVER_USECLASSVERSIONS
            = "signserver.useclassversions";
    private static final String PROPERTY_SIGNSERVER_REQUIRESIGNATURE
            = "signserver.requiresignature";
    private static final String PROPERTY_SIGNSERVER_PATHTOTRUSTSTORE
            = "signserver.pathtotruststore";
    private static final String PROPERTY_SIGNSERVER_TRUSTSTOREPWD
            = "signserver.truststorepwd";
    private static final String PROPERTY_SIGNSERVERCOMMANDFACTORY
            = "SignServerCommandFactory";
    private static final String PROPERTY_SIGNSERVER_CONFIGFILE
            = "signserver.configfile";
    private static final String PROPERTY_SIGNSERVER_VERSION
            = "signserver.version";

    /** Indicates if ClusterClassLoading should be enabled. */
    private static Boolean clusterClassLoaderEnabled;

    /** Indicates if ClusterClassLoading should support class versions. */
    private static Boolean useClassVersions;

    /** Indicates if ClusterClassLoading the full path to the jks trust store. */
    private static String pathToTrustStore;

    /** Indicates if ClusterClassLoading should require signing. */
    private static Boolean requireSigning;

    /**
     * The password to unlock the truststore password. Indicates if
     * ClusterClassLoading the full path to the jks trust store.
     */
    private static char[] cclTrustStorePWD;

    private Properties config;

    private String state;


    static {
        // Setup default properties
        DEFAULT_PROPERTIES.put(PROPERTY_BUILDMODE, "SIGNSERVER");
        DEFAULT_PROPERTIES.put(PROPERTY_SIGNSERVER_USECLUSTERCLASSLOADER,
                Boolean.toString(true));
        DEFAULT_PROPERTIES.put(PROPERTY_SIGNSERVER_USECLASSVERSIONS,
                Boolean.toString(true));
        DEFAULT_PROPERTIES.put(PROPERTY_SIGNSERVER_REQUIRESIGNATURE,
                Boolean.toString(false));

        // Load built-in compile-time properties
        try {
            final InputStream in = GlobalConfiguration.class
                    .getResourceAsStream("signservercompile.properties");
            if (in == null) {
                throw new FileNotFoundException("signservercompile.properties");
            }
            COMPILETIME_PROPERTIES.load(in);
        } catch (IOException ex) {
            throw new RuntimeException(
                    "Unable to load built-in signservercompile.properties", ex);
        }
    }


    /**
     * Constructor that should only be called within
     * the GlobalConfigurationSessionBean.
     */
    public GlobalConfiguration(Properties config, String state) {
        this.config = config;
        this.state = state;
    }

    /**
     * @return True if ClusterClassLoading should be enabled
     */
    public static boolean isClusterClassLoaderEnabled() {
        if (clusterClassLoaderEnabled == null) {
            clusterClassLoaderEnabled = Boolean.parseBoolean(
                    COMPILETIME_PROPERTIES.getProperty(
                    PROPERTY_SIGNSERVER_USECLUSTERCLASSLOADER).trim());
        }
        return clusterClassLoaderEnabled;
    }

    /**
     * @return True if ClusterClassLoading should support class versions
     */
    public static boolean isUseClassVersions() {
        if (useClassVersions == null) {
            useClassVersions = Boolean.parseBoolean(
                    COMPILETIME_PROPERTIES.getProperty(
                    PROPERTY_SIGNSERVER_USECLASSVERSIONS).trim());
        }
        return useClassVersions;
    }

    /**
     * @return True if ClusterClassLoading should require signing
     */
    public static boolean isRequireSigning() {
        if (requireSigning == null) {
            requireSigning = Boolean.parseBoolean(
                    COMPILETIME_PROPERTIES.getProperty(
                    PROPERTY_SIGNSERVER_REQUIRESIGNATURE).trim());
        }
        return requireSigning;
    }

    /**
     * @return the full path to the jks trust store
     */
    public static String getPathToTrustStore() {
        if (pathToTrustStore == null) {
            pathToTrustStore = COMPILETIME_PROPERTIES.getProperty(
                    PROPERTY_SIGNSERVER_PATHTOTRUSTSTORE);
        }
        return pathToTrustStore;
    }

    /**
     * @return the trust store password
     */
    public static char[] getCCLTrustStorePasswd() {
        if (cclTrustStorePWD == null) {
            final String trustStoreValue = COMPILETIME_PROPERTIES.getProperty(
                    PROPERTY_SIGNSERVER_TRUSTSTOREPWD);
            if (trustStoreValue == null || trustStoreValue.trim().isEmpty()) {
                LOG.error("Error cluster classloader truststore password isn't configured");
            } else {
                cclTrustStorePWD = trustStoreValue.toCharArray();
            }
        }
        return cclTrustStorePWD;
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
     * @param property the actual property (with  GLOB. or NODE. prefixes)
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
     * Returns the classpath of the worker with id
     *
     * Is backward compatible with the version 1 global configuration syntax
     * @param workerId
     * @return the defined classpath or null of it couldn't be found.
     */
    public String getWorkerClassPath(int workerId) {
        return getProperty(SCOPE_GLOBAL, WORKERPROPERTY_BASE
                + workerId + WORKERPROPERTY_CLASSPATH);
    }

    /**
     * Returns the property specific to a cryptotoken,
     * This should only be used with signers and not with
     * cryptotokens.
     *
     * @param workerId
     * @param cryptotokenproperty
     * @return return the given cryptotoken property or null.
     */
    public String getCryptoTokenProperty(int workerId,
            String cryptotokenproperty) {
        String key = WORKERPROPERTY_BASE + workerId
                + CRYPTOTOKENPROPERTY_BASE + cryptotokenproperty;
        if (getProperty(SCOPE_GLOBAL, key) == null) {
            key = WORKERPROPERTY_BASE + workerId
                    + OLD_CRYPTOTOKENPROPERTY_BASE + cryptotokenproperty;
        }
        return getProperty(SCOPE_GLOBAL, key);
    }

    /**
     * @return the version of the server
     */
    public String getAppVersion() {
        return COMPILETIME_PROPERTIES.getProperty(PROPERTY_SIGNSERVER_VERSION);
    }

    /**
     * @return the build mode
     */
    public static String getBuildMode() {
        return COMPILETIME_PROPERTIES.getProperty(PROPERTY_BUILDMODE).trim();
    }
}
