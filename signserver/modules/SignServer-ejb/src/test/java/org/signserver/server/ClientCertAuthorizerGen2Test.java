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
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.Test;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;
import org.signserver.common.RequestContext;
import org.signserver.common.WorkerConfig;
import org.signserver.common.data.Request;

/**
 * Tests for the new generation authorized clients.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ClientCertAuthorizerGen2Test {
    
    private static final int DUMMY_WORKER_ID = 4711;
    private static final String TEST_SERIALNUMBER = "123456789ab";
    private static final String TEST_SERIALNUMBER_WITH_LEADING_ZERO =
            "0123456789ab";
    private static final String TEST_ISSUER = "CN=foo,O=TestOrganization,C=SE";
    private static final String TEST_DESCRIPTION = "Test description";
    
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
    private String testAuthorized(final X509Certificate cert, final List<CertificateMatchingRule> authClients,
                              final boolean expectAuthorized)
            throws Exception {
        String errorMessage = "";
        final ClientCertAuthorizer instance = new ClientCertAuthorizer();
        final WorkerConfig config = new WorkerConfig();
        
        if (authClients != null) {
            authClients.forEach((client) -> {
                config.addAuthorizedClientGen2(client);
            });
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
     * Test matching on subject serial number and issuer DN expressed in BC style.
     * 
     * @throws Exception 
     */
    @Test
    public void testMatchSubjectSerialNumberIssuerDNBCStyle() throws Exception {
        final X509Certificate cert =
                ClientCertAuthorizerTestHelper.createBCCert(TEST_SERIALNUMBER, TEST_ISSUER);
        final CertificateMatchingRule rule =
                new CertificateMatchingRule(MatchSubjectWithType.CERTIFICATE_SERIALNO,
                                            MatchIssuerWithType.ISSUER_DN_BCSTYLE,
                                            TEST_SERIALNUMBER, TEST_ISSUER,
                                            TEST_DESCRIPTION);
        testAuthorized(cert, Arrays.asList(rule), true);
    }
    
    /**
     * Test matching on subject serial number with leading zero and issuer DN expressed in BC style.
     * 
     * @throws Exception 
     */
    @Test
    public void testMatchSubjectSerialNumberWithLeadingZeroIssuerDNBCStyle() throws Exception {
        final X509Certificate cert =
                ClientCertAuthorizerTestHelper.createBCCert(TEST_SERIALNUMBER, TEST_ISSUER);
        final CertificateMatchingRule rule =
                new CertificateMatchingRule(MatchSubjectWithType.CERTIFICATE_SERIALNO,
                                            MatchIssuerWithType.ISSUER_DN_BCSTYLE,
                                            TEST_SERIALNUMBER_WITH_LEADING_ZERO,
                                            TEST_ISSUER, TEST_DESCRIPTION);
        testAuthorized(cert, Arrays.asList(rule), true);
    }
}
