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
import java.util.Properties;
import org.apache.log4j.Logger;

/**
 * Settings loaded from built-in properties-file signservercompile.properties
 * put together during compilation.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class CompileTimeSettings {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            CompileTimeSettings.class);

    public static final String APPNAME
            = "appname";
    public static final String APPNAME_CAP
            = "appname_capital";
    public static final String RMIREGISTRYPORT
            = "rmiregistryport";
    public static final String RMISERVERPORT
            = "rmiserverport";
    public static final String MAILSIGNERPORT
            = "mailsignerport";
    public static final String BUILDMODE
            = "buildmode";
    public static final String DATASOURCE_JNDINAMEPREFIX
            = "datasource.jndi-name-prefix";
    public static final String DATASOURCE_JNDINAME
            = "datasource.jndi-name";
    public static final String HEALTHECK_AUTHORZEDIPS
            = "healthcheck.authorizedips";
    public static final String HEALTHECK_MINIMUMFREEMEMORY
            = "healthcheck.minimumfreememory";
    public static final String HEALTHECK_CHECKDBSTRING
            = "healthcheck.checkdbstring";
    public static final String SIGNSERVER_USECLUSTERCLASSLOADER
            = "signserver.useclusterclassloader";
    public static final String SIGNSERVER_USECLASSVERSIONS
            = "signserver.useclassversions";
    public static final String SIGNSERVER_REQUIRESIGNATURE
            = "signserver.requiresignature";
    public static final String SIGNSERVER_PATHTOTRUSTSTORE
            = "signserver.pathtotruststore";
    public static final String SIGNSERVER_TRUSTSTOREPWD
            = "signserver.truststorepwd";
    public static final String SIGNSERVERCOMMANDFACTORY
            = "SignServerCommandFactory";
    public static final String SIGNSERVER_CONFIGFILE
            = "signserver.configfile";
    public static final String SIGNSERVER_VERSION
            = "signserver.version";

    /** Default values for the compile-time properties. */
    private static final Properties DEFAULT_PROPERTIES = new Properties();

    private static CompileTimeSettings instance;

    /** Properties put together at compile-time. */
    private Properties properties = new Properties(DEFAULT_PROPERTIES);

    static {
        // Setup default properties
        DEFAULT_PROPERTIES.put(BUILDMODE, "SIGNSERVER");
        DEFAULT_PROPERTIES.put(SIGNSERVER_USECLUSTERCLASSLOADER,
                Boolean.toString(true));
        DEFAULT_PROPERTIES.put(SIGNSERVER_USECLASSVERSIONS,
                Boolean.toString(true));
        DEFAULT_PROPERTIES.put(SIGNSERVER_REQUIRESIGNATURE,
                Boolean.toString(false));
    }

    
    private CompileTimeSettings() {
        // Load built-in compile-time properties
        InputStream in = null;
        try {
            in = GlobalConfiguration.class
                    .getResourceAsStream("signservercompile.properties");
            if (in == null) {
                throw new FileNotFoundException("signservercompile.properties");
            }
            properties.load(in);
        } catch (IOException ex) {
            throw new RuntimeException(
                    "Unable to load built-in signservercompile.properties", ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOG.error("Error closing signservercompile.properties", ex);
                }
            }
        }
    }

    public static CompileTimeSettings getInstance() {
        if (instance == null) {
            instance = new CompileTimeSettings();
        }
        return instance;
    }

    public String getProperty(String key) {
        return properties.getProperty(key);
    }

}
