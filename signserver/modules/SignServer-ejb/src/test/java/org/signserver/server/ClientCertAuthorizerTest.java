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
import java.util.Arrays;
import java.util.List;
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
    
    private static final int DUMMY_WORKER_ID = 4711;
    private static final String TEST_SERIALNUMBER = "123456789ab";
    private static final String TEST_SERIALNUMBER_WITH_LEADING_ZERO =
            "0123456789ab";
    private static final String TEST_SERIALNUMBER_UPPER_CASE =
            "123456789AB";
    private static final String TEST_ISSUER = "CN=foo,O=TestOrganization,C=SE";
    
    private static final String OTHER_SERIALNUMBER = "a987654321";
    private static final String OTHER_ISSUER = "CN=other,O=OtherOrganization,C=SE";
    
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
     * Test assumed accepted request with specified configured auth client.
     * 
     * @param authClients List of authorized clients
     * @throws Exception 
     */
    private void testAuthorized(final List<AuthorizedClient> authClients,
                              final boolean expectAuthorized)
            throws Exception {
        final ClientCertAuthorizer instance = new ClientCertAuthorizer();
        final ProcessableConfig config =
                new ProcessableConfig(new WorkerConfig());
        
        if (authClients != null) {
            for (final AuthorizedClient client : authClients) {
                config.addAuthorizedClient(client); 
            }
        }
   
        instance.init(DUMMY_WORKER_ID, config.getWorkerConfig(), null);
        
        final ProcessRequest request = new GenericSignRequest();
        final RequestContext context = new RequestContext();
        
        context.put(RequestContext.CLIENT_CERTIFICATE, testCert);
        
        try {
            instance.isAuthorized(request, context);
            if (!expectAuthorized) {
                fail("Should not be authorized");
            }
        } catch (IllegalRequestException e) {
            if (expectAuthorized) {
                fail("Request should be authorized: " + e.getMessage());
            }
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
    }
    
    /**
     * Test assumed accepted request with specified configured auth client.
     * 
     * @param serialNumber Serial number of authorized client's cert
     * @param issuer Issuer DN of authorized client's cert
     * @throws Exception 
     */
    private void testAuthorized(final String serialNumber, final String issuer,
            final boolean expectAuthorized)
            throws Exception {
        testAuthorized(Arrays.asList(new AuthorizedClient(serialNumber, issuer)),
                expectAuthorized);
    }
    
    /**
     * Test a basic configuration with request cert matching configuration.
     * 
     * @throws Exception 
     */
    @Test
    public void test01AcceptedCert() throws Exception {
        testAuthorized(TEST_SERIALNUMBER, TEST_ISSUER, true);
    }
    
    /**
     * Test that specifying serial number with leading zero is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void test02AcceptedWithLeadingZero() throws Exception {
        testAuthorized(TEST_SERIALNUMBER_WITH_LEADING_ZERO, TEST_ISSUER, true);
    }
    
    /**
     * Test that requests are not authorized when there is no authorized clients
     * set.
     * 
     * @throws Exception 
     */
    @Test
    public void test03NotAcceptedWithNoAuthorizedClients() throws Exception {
        testAuthorized(null, false);
    }
    
    /**
     * Test that specifying serial number with upper case hex letters works.
     * 
     * @throws Exception 
     */
    @Test
    public void test04AcceptedWithUpperCaseHex() throws Exception {
        testAuthorized(TEST_SERIALNUMBER_UPPER_CASE, TEST_ISSUER, true);
    }
    
    /**
     * Test that specifying additional authorized clients, the original client
     * is still authorized.
     * 
     * @throws Exception 
     */
    @Test
    public void test05AcceptedWithAddionalAuthClient() throws Exception {
       testAuthorized(Arrays.asList(
               new AuthorizedClient(OTHER_SERIALNUMBER, OTHER_ISSUER),
               new AuthorizedClient(TEST_SERIALNUMBER, TEST_ISSUER)), true);
    }
    
    /**
     * Test that specifying a different authorized client, a request is not
     * accepted.
     * 
     * @throws Exception 
     */
    @Test
    public void test06NotAcceptedWithOtherClient() throws Exception {
       testAuthorized(OTHER_SERIALNUMBER, OTHER_ISSUER, false); 
    }
}
