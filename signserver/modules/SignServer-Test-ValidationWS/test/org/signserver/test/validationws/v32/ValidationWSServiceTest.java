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

    @Override
    protected String getWsEndPointUrl() {
    	return ENDPOINT;
    }
}
