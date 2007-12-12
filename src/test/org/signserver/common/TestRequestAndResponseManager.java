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

import junit.framework.TestCase;

import org.ejbca.util.KeyTools;
import org.signserver.validationservice.server.ValidationTestUtils;

public class TestRequestAndResponseManager extends TestCase {
	
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

}
