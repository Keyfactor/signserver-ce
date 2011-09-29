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
package org.signserver.validationservice.server;

import java.io.File;
import java.net.URL;
import java.security.cert.X509CRL;
import junit.framework.TestCase;
import org.apache.log4j.Logger;
import org.signserver.common.SignServerUtil;

/**
 * Test cases for the ValidationUtils class.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class ValidationUtilsTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(ValidationUtilsTest.class);

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        SignServerUtil.installBCProvider();
    }

    /**
    * Tests to fetch a CRL from an URL.
    * @throws Exception in case of error
    */
    public void test01fetchCRLFromURL() throws Exception {  	
        File homeFolder = new File(System.getenv("SIGNSERVER_HOME"));
        assertTrue("No such folder: " + homeFolder.getAbsolutePath(), homeFolder.exists());
        File crlFile = new File(homeFolder, "src/test/dss10/DSSRootCA10-1.crl");
        assertTrue("No such file: " + crlFile.getAbsolutePath(), crlFile.exists());
        URL crlURL = crlFile.toURI().toURL();
        X509CRL crl = ValidationUtils.fetchCRLFromURL(crlURL);
        assertNotNull("null crl", crl);
    }

}
