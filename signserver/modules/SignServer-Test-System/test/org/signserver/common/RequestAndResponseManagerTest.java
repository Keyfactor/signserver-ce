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

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

import junit.framework.TestCase;
import org.apache.log4j.Logger;

import org.ejbca.util.keystore.KeyTools;
import org.signserver.validationservice.server.ValidationTestUtils;

/**
 *
 * @version $Id$
 */
public class RequestAndResponseManagerTest extends TestCase {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(RequestAndResponseManagerTest.class);
    

	public void testParsing() throws Exception{
		SignServerUtil.installBCProvider();
		
		byte[] data = {123,123,123,123,123,123,123,123,123,123};
        GenericSignRequest request = new GenericSignRequest(12, data);
        
        byte[] requestData = RequestAndResponseManager.serializeProcessRequest(request);
        
        ProcessRequest request2 = RequestAndResponseManager.parseProcessRequest(requestData);
        assertTrue(request2 instanceof GenericSignRequest);
        assertTrue(((GenericSignRequest) request2).getRequestID() == 12);
        
        GenericSignResponse resp = new GenericSignResponse(13, data, null,null,null);
        byte[] respData = RequestAndResponseManager.serializeProcessResponse(resp);
        ProcessResponse r = RequestAndResponseManager.parseProcessResponse(respData);
        assertTrue(r instanceof GenericSignResponse);
        assertTrue(((GenericSignResponse) r).getRequestID() == 13);
        
		KeyPair validCert1Keys = KeyTools.genKeys("512", "RSA");
		X509Certificate cert = ValidationTestUtils.genCert("CN=ValidCert1", "CN=ValidSubCA1", validCert1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false);
        resp = new GenericSignResponse(13, data, cert,null,null);
        respData = RequestAndResponseManager.serializeProcessResponse(resp);
        r = RequestAndResponseManager.parseProcessResponse(respData);
        assertTrue(r instanceof GenericSignResponse);
        assertTrue(((GenericSignResponse) r).getRequestID() == 13);
        assertTrue(((GenericSignResponse) r).getSignerCertificate() != null);
	}

    /**
     * Tests externalization and parsing of a GenericPropertiesRequest.
     * @throws Exception In case of error.
     */
    public void testGenericPropertiesRequest() throws Exception {
        
        // Externalize a request
        final Properties requestData = new Properties();
        requestData.setProperty("aKey", "aValue");
        requestData.setProperty("AnotherKey", "A value with \"quotation\"");
        final GenericPropertiesRequest request1
                = new GenericPropertiesRequest(requestData);
        LOG.debug("Request: " + request1);
        final byte[] externalized
                = RequestAndResponseManager.serializeProcessRequest(request1);
        LOG.debug("Externalized length: " + externalized.length);

        // Parse the request
        final ProcessRequest request2
                = RequestAndResponseManager.parseProcessRequest(externalized);
        
        // We should now have back an equal request
        assertTrue(request2 instanceof GenericPropertiesRequest);
        assertEquals(request1, request2);
    }

    /**
     * Tests externalization and parsing of a GenericPropertiesResponse.
     * @throws Exception In case of error.
     */
    public void testGenericPropertiesResponse() throws Exception {

        // Externalize a response
        final Properties responseData = new Properties();
        responseData.setProperty("aKey", "aValue");
        responseData.setProperty("AnotherKey", "A value with \"quotation\"");
        final GenericPropertiesResponse response1
                = new GenericPropertiesResponse(responseData);
        final byte[] externalized
                = RequestAndResponseManager.serializeProcessResponse(response1);

        // Parse the response
        final ProcessResponse response2
                = RequestAndResponseManager.parseProcessResponse(externalized);

        // We should now have back an equal request
        assertTrue(response2 instanceof GenericPropertiesResponse);
        assertEquals(response1, response2);
    }

}
