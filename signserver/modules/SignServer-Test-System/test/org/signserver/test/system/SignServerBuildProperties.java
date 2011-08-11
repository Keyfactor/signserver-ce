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
package org.signserver.test.system;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.apache.log4j.Logger;

/**
 * Settings loaded from signserver_build.properties
 * put together during compilation.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SignServerBuildProperties {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            SignServerBuildProperties.class);
    
    public static final String DATASOURCE_JNDINAMEPREFIX
            = "datasource.jndi-name-prefix";
    public static final String DATASOURCE_JNDINAME
            = "datasource.jndi-name";
    
    /** Default values for the compile-time properties. */
    private static final Properties DEFAULT_PROPERTIES = new Properties();
    
    private static SignServerBuildProperties instance;
    
    /** Properties put together at compile-time. */
    private Properties properties = new Properties(DEFAULT_PROPERTIES);

    static {
        // Setup default properties
        DEFAULT_PROPERTIES.put(DATASOURCE_JNDINAMEPREFIX, "java:/");
        DEFAULT_PROPERTIES.put(DATASOURCE_JNDINAME, "SignServerDS");
    }

    private SignServerBuildProperties() {
        // Load built-in compile-time properties
        InputStream in = null;
        try {
            in = new FileInputStream(new File(System.getenv("SIGNSERVER_HOME"),
                    "signserver_build.properties"));
            properties.load(in);
        } catch (IOException ex) {
            throw new RuntimeException(
                    "Unable to load built-in signserver_build.properties", ex);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex) {
                    LOG.error("Error closing signserver_build.properties", ex);
                }
            }
        }
    }

    public static SignServerBuildProperties getInstance() {
        if (instance == null) {
            instance = new SignServerBuildProperties();
        }
        return instance;
    }

    public String getProperty(String key) {
        return properties.getProperty(key);
    }
}
