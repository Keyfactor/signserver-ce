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
package org.signserver.test.validationws.v32;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;
import org.apache.log4j.Logger;

/**
 * Test calling ValidationWSService using SignServer 3.2 WSDL.
 * (The WS end-point URL changed between 3.1 and 3.2.)
 *
 * This tests assumes that test-configuration.properties as been applied to
 * SignServer.
 *
 * @version $Id$
 */
public class ValidationWSServiceTest extends org.signserver.test.validationws.v31.ValidationWSServiceTest {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(ValidationWSServiceTest.class);

    /** Endpoint URL. */
    private static final String ENDPOINT = "https://localhost:8442/signserver/ValidationWSService/ValidationWS?wsdl";

    public ValidationWSServiceTest(String testName) {
        super(testName);
        setupKeystores();
    }

    /** Setup keystores for SSL. **/
    private void setupKeystores() {
        Properties config = new Properties();
        try {
            config.load(new FileInputStream(new File("../../signserver_build.properties")));
        } catch (FileNotFoundException ignored) {
            LOG.debug("No signserver_build.properties");
        } catch (IOException ex) {
            LOG.error("Not using signserver_build.properties: " + ex.getMessage());
        }
        System.setProperty("javax.net.ssl.trustStore", "../../p12/truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword",
                config.getProperty("java.trustpassword", "changeit"));
        //System.setProperty("javax.net.ssl.keyStore", "../../p12/testadmin.jks");
        //System.setProperty("javax.net.ssl.keyStorePassword", "foo123");
    }

    @Override
    protected String getWsEndPointUrl() {
    	return ENDPOINT;
    }
}
