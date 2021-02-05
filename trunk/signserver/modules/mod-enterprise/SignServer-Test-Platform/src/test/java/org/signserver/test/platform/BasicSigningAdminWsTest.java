/*************************************************************************
 *                                                                       *
 *  SignServer Enterprise - Proprietary Modules.                         *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.signserver.test.platform;

import java.io.File;
import java.io.FileNotFoundException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Properties;
import javax.xml.namespace.QName;
import org.apache.log4j.Logger;
import org.junit.After;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.Test;
import org.signserver.test.platform.adminws.gen.*;
import org.signserver.testutils.ModulesTestCase;

/**
 * Tests to verify that a signer can be setup (using AdminWS) and used
 * for signing.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class BasicSigningAdminWsTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(BasicSigningAdminWsTest.class);

    private final ModulesTestCase testCase = new ModulesTestCase();

    /** Setup keystores for TLS. **/
    private void setupKeystores() throws FileNotFoundException {
        
        final File home = testCase.getSignServerHome();
        final Properties config = testCase.getConfig();
        
        LOG.warn("This test cases assumes the following:\n"
            + "- A truststore called p12/truststore.jks with password changeit containing the CA certificate that issued the TLS server certificate. Preferably use res/test/dss10_truststore.jks assuming the server uses dss10_demo-tls.jks.\n"
            + "- A keystore called p12/client.p12. Preferably use res/test/dss10/dss10_admin1.p12 assuming the truststore accepts certs issued by DSSRootCA10\n");
        
        final File truststore = new File(home, "p12/truststore.jks");
        if (!truststore.exists()) {
            throw new FileNotFoundException("No p12/truststore.jks");
        }

        final File keystore = new File(home, "p12/client.p12");
        if (!keystore.exists()) {
            throw new FileNotFoundException("No p12/client.p12");
        }

        System.setProperty("javax.net.ssl.trustStore", truststore.getAbsolutePath());
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        System.setProperty("javax.net.ssl.keyStore", keystore.getAbsolutePath());
        System.setProperty("javax.net.ssl.keyStorePassword", "foo123");
    }

    @Before
    public void setUp() throws Exception {
        setupKeystores();
    }

    @After
    public void tearDown() throws Exception {
    }
    
    private AdminWS createAdminWS(final boolean privatePort) throws MalformedURLException {
        final AdminWSService service = new AdminWSService(
                new URL("https://" + testCase.getHTTPHost() + ":" + (privatePort ? testCase.getPrivateHTTPSPort() : testCase.getPublicHTTPSPort()) + "/signserver/AdminWSService/AdminWS?wsdl"),
                new QName("http://adminws.signserver.org/",
                    "AdminWSService"));
        return service.getAdminWSPort();
    }
    
    
    /**
     * Tests that an authorization exception is thrown when trying to access 
     * using the port that does not require client authentication.
     * @throws Exception 
     */
    @Test(expected = AdminNotAuthorizedException_Exception.class)
    public void testAuthorizationFailureWithoutClientAuth() throws Exception{
        LOG.info("testAuthorizationFailureWithoutClientAuth");
    
        final boolean clientAuth = false;
        final AdminWS adminWS = createAdminWS(clientAuth);
        final WsGlobalConfiguration global = adminWS.getGlobalConfiguration();
        LOG.debug("App version: " + global.getAppVersion());
    }
    
    /**
     * Tests that AdminWS is working by getting the global configuration.
     * @throws Exception 
     */
    @Test
    public void testGetGlobalConfiguration() throws Exception{
        LOG.info("testGetGlobalConfiguration");
        
        final AdminWS adminWS = createAdminWS(true);
        final WsGlobalConfiguration global = adminWS.getGlobalConfiguration();
        LOG.debug("App version: " + global.getAppVersion());
        assertNotNull("App version", global.getAppVersion());
    }
    
    // Future: Add additional test cases here that sets up signers and performs
    // signings etc.

}
