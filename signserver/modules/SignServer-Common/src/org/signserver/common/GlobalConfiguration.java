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
    public static final int WORKERTYPE_ALL = 1;
    public static final int WORKERTYPE_PROCESSABLE = 2;
    public static final int WORKERTYPE_SERVICES = 3;
    public static final int WORKERTYPE_MAILSIGNERS = 4;
    public static final String WORKERPROPERTY_BASE = "WORKER";
    public static final String WORKERPROPERTY_CLASSPATH = ".CLASSPATH";
    public static final String CRYPTOTOKENPROPERTY_BASE = ".CRYPTOTOKEN";
    public static final String OLD_CRYPTOTOKENPROPERTY_BASE = ".SIGNERTOKEN";
    public static final String CRYPTOTOKENPROPERTY_CLASSPATH = ".CLASSPATH";

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
                    CompileTimeSettings.getInstance().getProperty(
                    CompileTimeSettings.SIGNSERVER_USECLUSTERCLASSLOADER).trim());
        }
        return clusterClassLoaderEnabled;
    }

    /**
     * @return True if ClusterClassLoading should support class versions
     */
    public static boolean isUseClassVersions() {
        if (useClassVersions == null) {
            useClassVersions = Boolean.parseBoolean(
                    CompileTimeSettings.getInstance().getProperty(
                    CompileTimeSettings.SIGNSERVER_USECLASSVERSIONS).trim());
        }
        return useClassVersions;
    }

    /**
     * @return True if ClusterClassLoading should require signing
     */
    public static boolean isRequireSigning() {
        if (requireSigning == null) {
            requireSigning = Boolean.parseBoolean(
                    CompileTimeSettings.getInstance().getProperty(
                    CompileTimeSettings.SIGNSERVER_REQUIRESIGNATURE).trim());
        }
        return requireSigning;
    }

    /**
     * @return the full path to the jks trust store
     */
    public static String getPathToTrustStore() {
        if (pathToTrustStore == null) {
            pathToTrustStore = CompileTimeSettings.getInstance().getProperty(
                    CompileTimeSettings.SIGNSERVER_PATHTOTRUSTSTORE);
        }
        return pathToTrustStore;
    }

    /**
     * @return the trust store password
     */
    public static char[] getCCLTrustStorePasswd() {
        if (cclTrustStorePWD == null) {
            final String trustStoreValue = CompileTimeSettings.getInstance().getProperty(CompileTimeSettings.SIGNSERVER_TRUSTSTOREPWD);
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
        return CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.SIGNSERVER_VERSION);
    }

    /**
     * @return the build mode
     */
    public static String getBuildMode() {
        return CompileTimeSettings.getInstance().getProperty(
                CompileTimeSettings.BUILDMODE).trim();
    }
}
