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

	/** Endpoint URL. */
	private static final String ENDPOINT = "http://localhost:8080/signserver/ValidationWSService/ValidationWS?wsdl";

    public ValidationWSServiceTest(String testName) {
        super(testName);
    }

    @Override
    protected String getWsEndPointUrl() {
    	return ENDPOINT;
    }
}
