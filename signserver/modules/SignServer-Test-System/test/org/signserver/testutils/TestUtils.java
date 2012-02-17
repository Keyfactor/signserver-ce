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
package org.signserver.testutils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;
import org.apache.log4j.Logger;

/**
 * Class containing utility methods used to simplify testing.
 *
 * @author Philip Vendil 21 okt 2007
 * @version $Id$
 */
public class TestUtils {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TestUtils.class);
    
    private Properties buildConfig;
    
    public void setupSSLTruststore() {
        System.setProperty("javax.net.ssl.trustStore", 
                getTruststoreFile().getAbsolutePath());
        System.setProperty("javax.net.ssl.trustStorePassword",
                getTrustStorePassword());
        //System.setProperty("javax.net.ssl.keyStore", "../../p12/testadmin.jks");
        //System.setProperty("javax.net.ssl.keyStorePassword", "foo123");
    }
    
    private Properties getBuildConfig() {
        if (buildConfig == null) {
            buildConfig = new Properties();
            File confFile1 = new File("../../signserver_build.properties");
            File confFile2 = new File("../../conf/signserver_build.properties");
            try {
                if (confFile1.exists()) {
                    buildConfig.load(new FileInputStream(confFile1));
                } else {
                    buildConfig.load(new FileInputStream(confFile2));
                }
            } catch (FileNotFoundException ignored) {
                LOG.debug("No signserver_build.properties");
            } catch (IOException ex) {
                LOG.error("Not using signserver_build.properties: " + ex.getMessage());
            }
        }
        return buildConfig;
    }
    
    public File getTruststoreFile() {
        return new File(System.getenv("SIGNSERVER_HOME"), "p12/truststore.jks");
    }
     
    public String getTrustStorePassword() {
        return getBuildConfig().getProperty("java.trustpassword", "changeit");
    }
}
