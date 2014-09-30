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
package org.signserver.server;

import java.math.BigInteger;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.ProcessRequest;
import org.signserver.common.ProcessableConfig;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.test.utils.builders.CertBuilder;


/**
 * Test cases for the client certificate authorizer.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ClientCertAuthorizerTest {
    
    private static int DUMMY_WORKER_ID = 4711;
    private static String TEST_SERIALNUMBER = "123456789";
    private static String TEST_ISSUER = "CN=foo,O=TestOrganization,C=SE";
    
    private X509Certificate testCert;
    
    @Before
    public void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        final CertBuilder builder = new CertBuilder();
        final JcaX509CertificateConverter conv =
                new JcaX509CertificateConverter();
        
        builder.setSerialNumber(new BigInteger(TEST_SERIALNUMBER, 16));
        builder.setIssuer(TEST_ISSUER);
        
        testCert = conv.getCertificate(builder.build());
    }
    
    /**
     * Test a basic configuration with request cert matching configuration.
     * 
     * @throws Exception 
     */
    @Test
    public void test01AcceptedCert() throws Exception {
        final ClientCertAuthorizer instance = new ClientCertAuthorizer();
        final ProcessableConfig config =
                new ProcessableConfig(new WorkerConfig());
        
        config.addAuthorizedClient(new AuthorizedClient(TEST_SERIALNUMBER,
                                                        TEST_ISSUER)); 
        
        instance.init(DUMMY_WORKER_ID, config.getWorkerConfig(), null);
        
        final ProcessRequest request = new GenericSignRequest();
        final RequestContext context = new RequestContext();
        
        context.put(RequestContext.CLIENT_CERTIFICATE, testCert);
        
        try {
            instance.isAuthorized(request, context);
            // should pass
        } catch (IllegalRequestException e) {
            fail("Request should be authorized: " + e.getMessage());
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
}
