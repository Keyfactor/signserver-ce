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
package org.signserver.adminws.client;

import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

import javax.xml.namespace.QName;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;


/**
 * Tests for the Admin WS interface when Allow Any is enabled and can be edited, removed and added to be true.
 * These tests require the admin.allowany.enabled property in signserver_deploy.properties to be set to true
 * in order to work as intended and test.admin.allowany=true to be set in test-config.properties in order to
 * run the tests.
 *
 * @author Christofer Vikström
 * @author Oscar Norman
 */
public class AllowAnyEnabledDeployPropTest extends ModulesTestCase {


    /** Logger for this class. **/
    private static final Logger LOG = Logger.getLogger(AllowAnyEnabledDeployPropTest.class);;

    private static final String[] CONF_FILES = {
            "signserver_deploy.properties",
            "conf/signserver_deploy.properties",
    };

    private AdminWS adminWS;
    private final CLITestHelper adminCLI = getAdminCLI();

    public AllowAnyEnabledDeployPropTest() {
        setupKeystores();
    }

    /** Setup keystores for SSL. **/
    private void setupKeystores() {
        Properties config = new Properties();

        final File home;
        final File path1 = new File("../..");
        final File path2 = new File(".");
        if (new File(path1, "res/deploytools/app.properties").exists()) {
            home = path1;
        } else if (new File(path2, "res/deploytools/app.properties").exists()) {
            home = path2;
        } else {
            throw new RuntimeException("Unable to detect SignServer path");
        }

        File confFile = null;
        for (String file : CONF_FILES) {
            final File f = new File(home, file);
            if (f.exists()) {
                confFile = f;
                break;
            }
        }
        if (confFile == null) {
            throw new RuntimeException("No signserver_deploy.properties found");
        } else {

            try {
                config.load(new FileInputStream(confFile));
            } catch (FileNotFoundException ignored) {
                LOG.debug("No signserver_deploy.properties");
            } catch (IOException ex) {
                LOG.error("Not using signserver_deploy.properties: " + ex.getMessage());
            }

            final String truststore = new File(home, "res/test/dss10/dss10_truststore.jks").getAbsolutePath();
            final String keystore = new File(home, "res/test/dss10/dss10_admin1.p12").getAbsolutePath();
            System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
            System.setProperty("javax.net.ssl.keyStore", keystore);
            System.setProperty("javax.net.ssl.trustStore", truststore);
            System.setProperty("javax.net.ssl.keyStorePassword", "foo123");
        }
    }

    @Before
    public void setUp() throws Exception {
        final boolean enabled =
                Boolean.TRUE.toString().equalsIgnoreCase(getConfig().getProperty("test.admin.allowany"));
        Assume.assumeTrue("Assumes test.admin.allowany.enabled=false in test-config.properties",
                enabled);

        adminCLI.execute("wsadmins", "-allowany", "true");
        final AdminWSService service = new AdminWSService(
                new URL("https://" + getHTTPHost() + ":8443/signserver/AdminWSService/AdminWS?wsdl"),
                new QName("http://adminws.signserver.org/",
                        "AdminWSService"));
        adminWS = service.getAdminWSPort();
    }

    @After
    public void tearDown() throws Exception {
        adminCLI.execute("wsadmins", "-allowany", "false");
    }

    /**
     * Test that ALLOWANYWSADMIN can be edited to true when admin.allowany.enabled is true.
     */
    @Test
    public void testAllowAnyEnabledForEditingToTrue() {
        try {
            adminWS.setGlobalProperty("GLOB.", "ALLOWANYWSADMIN", "true");
        } catch (AdminNotAuthorizedException_Exception ex) {
            fail("This test requires admin.allowany.enabled=true to be configured when SignServer is deployed and should not throw exception");
        }
    }

    /**
     * Test that ALLOWANYWSADMIN can be edited to false even when admin.allowany.enabled is true.
     */
    @Test
    public void testAllowAnyEnabledForEditingToFalse() {
        try {
            adminWS.setGlobalProperty("GLOB.", "ALLOWANYWSADMIN", "false");
        } catch (AdminNotAuthorizedException_Exception ex) {
            fail("Allow any should always be possible to edit to false");
        }
    }

    /**
     * Test that ALLOWANYWSADMIN can be removed as a Global Configuration property when admin.allowany.enabled.
     */
    @Test
    public void testRemovingWhenAllowAnyEnabled() {
        try {
            adminWS.removeGlobalProperty("GLOB.", "ALLOWANYWSADMIN");
        } catch (AdminNotAuthorizedException_Exception ex) {
            fail("Allow any should be removable whenever admin.allowany.disabled is not false");
        }
    }

}
