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

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.util.CertTools;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;


/**
 * Test cases for the client certificate authorizer.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ClientCertAuthorizerUnitTest {

    private static final int DUMMY_WORKER_ID = 4711;
    private static final String TEST_SERIALNUMBER = "123456789ab";
    private static final String TEST_SERIALNUMBER_WITH_LEADING_ZERO =
            "0123456789ab";
    private static final String TEST_SERIALNUMBER_UPPER_CASE =
            "123456789AB";
    private static final String TEST_SERIALNUMBER2 = "222bbb";
    private static final String TEST_SERIALNUMBER3 = "333ccc";
    private static final String TEST_ISSUER = "CN=foo,O=TestOrganization,C=SE";
    private static final String TEST_ISSUER2 = "CN=foo2,O=Organization 2\\, inc.,C=SE";
    private static final String TEST_ISSUER3 = "C=SE,O=Organization 2\\, inc.,CN=foo2";

    private static final String OTHER_SERIALNUMBER = "a987654321";
    private static final String OTHER_ISSUER = "CN=other,O=OtherOrganization,C=SE";
    private static final String OTHER_ISSUER2 = "CN=foo2,O=Organization 2 inc.,C=SE"; // Same as TEST_ISSUER2 but without "," in organization


    @Before
    public void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Test assumed accepted request with specified configured auth client.
     * 
     * @param authClients List of authorized clients
     * @throws Exception 
     * @return Error message (if one)
     */
    private String testAuthorized(final X509Certificate cert, final List<AuthorizedClient> authClients,
                              final boolean expectAuthorized)
            throws Exception {
        String errorMessage = "";
        final ClientCertAuthorizer instance = new ClientCertAuthorizer();
        final WorkerConfig config = new WorkerConfig();
        
        if (authClients != null) {
            for (final AuthorizedClient client : authClients) {
                config.addAuthorizedClient(client); 
            }
        }
   
        instance.init(DUMMY_WORKER_ID, config, null);
        
        final Request request = null;
        final RequestContext context = new RequestContext();
        
        context.put(RequestContext.CLIENT_CERTIFICATE, cert);
        
        try {
            instance.isAuthorized(request, context);
            if (!expectAuthorized) {
                fail("Should not be authorized");
            }
        } catch (IllegalRequestException e) {
            if (expectAuthorized) {
                fail("Request should be authorized: " + e.getMessage());
            }
            errorMessage = e.getMessage();
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getClass().getName());
        }
        return errorMessage;
    }
    
    /**
     * Test assumed accepted request with specified configured auth client.
     * 
     * @param serialNumber Serial number of authorized client's cert
     * @param issuer Issuer DN of authorized client's cert
     * @throws Exception 
     * @return Error message (if one)
     */
    private String testAuthorized(final X509Certificate cert, final String serialNumber, final String issuer, final boolean expectAuthorized)
            throws Exception {
        return testAuthorized(cert, Arrays.asList(new AuthorizedClient(serialNumber, issuer)),
                expectAuthorized);
    }
    
    /**
     * Test a basic configuration with request cert matching configuration.
     * 
     * @throws Exception 
     */
    @Test
    public void test01AcceptedCert() throws Exception {
        testAuthorized(ClientCertAuthorizerTestHelper.createCert(TEST_SERIALNUMBER, TEST_ISSUER),
                TEST_SERIALNUMBER, TEST_ISSUER, true);
    }
    
    /**
     * Test that specifying serial number with leading zero is supported.
     * 
     * @throws Exception 
     */
    @Test
    public void test02AcceptedWithLeadingZero() throws Exception {
        testAuthorized(ClientCertAuthorizerTestHelper.createCert(TEST_SERIALNUMBER, TEST_ISSUER),
                TEST_SERIALNUMBER_WITH_LEADING_ZERO, TEST_ISSUER, true);
    }
    
    /**
     * Test that requests are not authorized when there is no authorized clients
     * set.
     * 
     * @throws Exception 
     */
    @Test
    public void test03NotAcceptedWithNoAuthorizedClients() throws Exception {
        testAuthorized(ClientCertAuthorizerTestHelper.createCert(TEST_SERIALNUMBER, TEST_ISSUER),
                null, false);
    }
    
    /**
     * Test that specifying serial number with upper case hex letters works.
     * 
     * @throws Exception 
     */
    @Test
    public void test04AcceptedWithUpperCaseHex() throws Exception {
        testAuthorized(ClientCertAuthorizerTestHelper.createCert(TEST_SERIALNUMBER, TEST_ISSUER),
                TEST_SERIALNUMBER_UPPER_CASE, TEST_ISSUER, true);
    }
    
    /**
     * Test that specifying additional authorized clients, the original client
     * is still authorized.
     * 
     * @throws Exception 
     */
    @Test
    public void test05AcceptedWithAddionalAuthClient() throws Exception {
       testAuthorized(ClientCertAuthorizerTestHelper.createCert(TEST_SERIALNUMBER, TEST_ISSUER), Arrays.asList(
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
       testAuthorized(ClientCertAuthorizerTestHelper.createCert(TEST_SERIALNUMBER, TEST_ISSUER),
               OTHER_SERIALNUMBER, OTHER_ISSUER, false);
    }

    /**
     * Tests that the usage of getIssuerX500Principle and
     * CertTools.stringToBCDNString yields the same and the expected results
     * both for Sun and BC certificates.
     * Tests with a simple DN.
     * @throws Exception
     */
    @Test
    public void testSameDNWithSunAndBCCerts_simple() throws Exception {
        X509Certificate certSun = ClientCertAuthorizerTestHelper.createCert(TEST_SERIALNUMBER, TEST_ISSUER);
        X509Certificate certBC = ClientCertAuthorizerTestHelper.createBCCert(TEST_SERIALNUMBER, TEST_ISSUER);

        String rfc2253Sun = certSun.getIssuerX500Principal().getName();
        String rfc2253BC = certBC.getIssuerX500Principal().getName();
        assertEquals("DN", rfc2253Sun, rfc2253BC);

        String bcdnSun = CertTools.stringToBCDNString(rfc2253Sun);
        String bcdnBC = CertTools.stringToBCDNString(rfc2253BC);
        assertEquals("DN normalized", bcdnSun, bcdnBC);

        assertEquals("DN bc style", "CN=foo,O=TestOrganization,C=SE", bcdnSun);
    }

    /**
     * Tests that the usage of getIssuerX500Principle and
     * CertTools.stringToBCDNString yields the same and the expected results
     * both for Sun and BC certificates.
     * Tests with a DN that contains an escaped character.
     * @throws Exception
     */
    @Test
    public void testSameDNWithSunAndBCCerts_escaped() throws Exception {
        X509Certificate certSun = ClientCertAuthorizerTestHelper.createCert(TEST_SERIALNUMBER2, TEST_ISSUER2);
        X509Certificate certBC = ClientCertAuthorizerTestHelper.createBCCert(TEST_SERIALNUMBER2, TEST_ISSUER2);

        String rfc2253Sun = certSun.getIssuerX500Principal().getName();
        String rfc2253BC = certBC.getIssuerX500Principal().getName();
        assertEquals("DN", rfc2253Sun, rfc2253BC);

        String bcdnSun = CertTools.stringToBCDNString(rfc2253Sun);
        String bcdnBC = CertTools.stringToBCDNString(rfc2253BC);
        assertEquals("DN normalized", bcdnSun, bcdnBC);

        assertEquals("DN bc style", "CN=foo2,O=Organization 2\\, inc.,C=SE", bcdnSun);
    }

    /**
     * Tests that the usage of getIssuerX500Principle and
     * CertTools.stringToBCDNString yields the same and the expected results
     * both for Sun and BC certificates.
     * Tests with a DN that is in reverse order and contains an escaped
     * character.
     * @throws Exception
     */
    @Test
    public void testSameDNWithSunAndBCCerts_escapedReversed() throws Exception {
        X509Certificate certSun = ClientCertAuthorizerTestHelper.createCert(TEST_SERIALNUMBER3, TEST_ISSUER3);
        X509Certificate certBC = ClientCertAuthorizerTestHelper.createBCCert(TEST_SERIALNUMBER3, TEST_ISSUER3);

        String rfc2253Sun = certSun.getIssuerX500Principal().getName();
        String rfc2253BC = certBC.getIssuerX500Principal().getName();
        assertEquals("DN", rfc2253Sun, rfc2253BC);

        String bcdnSun = CertTools.stringToBCDNString(rfc2253Sun);
        String bcdnBC = CertTools.stringToBCDNString(rfc2253BC);
        assertEquals("DN normalized", bcdnSun, bcdnBC);

        assertEquals("DN bc style", "CN=foo2,O=Organization 2\\, inc.,C=SE", bcdnSun);
    }

    /**
     * Test with cert including escaped character is accepted.
     * Using BC certificate.
     * @throws Exception
     */
    @Test
    public void testAcceptedIssuerWithComma_bc() throws Exception {
        testAuthorized(ClientCertAuthorizerTestHelper.createBCCert(TEST_SERIALNUMBER2, TEST_ISSUER2),
                TEST_SERIALNUMBER2, TEST_ISSUER2, true);
    }

    /**
     * Test with cert including escaped character is not accepted as well as
     * that the error message has the DN printed as expected.
     * Using BC certificate.
     * @throws Exception
     */
    @Test
    public void testNoAcceptedIssuerWithCommaOtherClient_bc() throws Exception {
        String message = testAuthorized(ClientCertAuthorizerTestHelper.createBCCert(TEST_SERIALNUMBER2, TEST_ISSUER2),
                TEST_SERIALNUMBER2, OTHER_ISSUER2, false);

        // Check that the DN in the error message is represented as expected.
        assertTrue("message: " + message, message.contains(TEST_ISSUER2));
    }

    /**
     * Test with cert including escaped character is accepted.
     * Using Sun certificate.
     * @throws Exception
     */
    @Test
    public void testAcceptedIssuerWithComma_sun() throws Exception {
        testAuthorized(ClientCertAuthorizerTestHelper.createCert(TEST_SERIALNUMBER2, TEST_ISSUER2),
                TEST_SERIALNUMBER2, TEST_ISSUER2, true);
    }

    /**
     * Test with cert including escaped character is not accepted as well as
     * that the error message has the DN printed as expected.
     * Using Sun certificate.
     * @throws Exception
     */
    @Test
    public void testNoAcceptedIssuerWithCommaOtherClient_sun() throws Exception {
        String message = testAuthorized(ClientCertAuthorizerTestHelper.createCert(TEST_SERIALNUMBER2, TEST_ISSUER2),
                TEST_SERIALNUMBER2, OTHER_ISSUER2, false);

        // Check that the DN in the error message is represented as expected.
        assertTrue("message: " + message, message.contains(TEST_ISSUER2));
    }
}
