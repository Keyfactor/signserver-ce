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

import java.security.cert.Certificate;
import org.apache.log4j.Logger;
import org.signserver.common.*;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestUtils;

/**
 * Tests limits for the key usages.
 *
 * @author Markus Kilas
 * @version $Id$
 */
public class LimitKeyUsagesTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(
            LimitKeyUsagesTest.class);
    
    /** WORKERID used in this test case. */
    private static final int WORKERID_1 = 5802;
    
    /**
     * Test with this number of signings.
     */
    private static final int LIMIT = 10;

    @Override
    protected void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Override
    protected void tearDown() throws Exception {
    }

    public void test00SetupDatabase() throws Exception {
        addSoftDummySigner(WORKERID_1, "TestLimitKeyUsageSigner", "AAAAojCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArIHGOBjP7WZdbgVbw61FzswgtZYhnsVW4ZRskPYcYbjXFO7Hf5zBWC6c/C+vb9w4AvdgEFvzHLtP9qJ+bcJAZw6VvFcZnLgEbPHCwXSVVFIsY2/OJ6ys6GOAAX/inLpvTjkUSzCoB28s4yYGaZXv7v77pjsjODYpDz4W5UCx9AcCAwEAAQAAAnowggJ2AgEAMA0GCSqGSIb3DQEBAQUABIICYDCCAlwCAQACgYEArIHGOBjP7WZdbgVbw61FzswgtZYhnsVW4ZRskPYcYbjXFO7Hf5zBWC6c/C+vb9w4AvdgEFvzHLtP9qJ+bcJAZw6VvFcZnLgEbPHCwXSVVFIsY2/OJ6ys6GOAAX/inLpvTjkUSzCoB28s4yYGaZXv7v77pjsjODYpDz4W5UCx9AcCAwEAAQKBgF2f/WXayZbuFM0uqVQ1SYroLOSA+/RA5FuAA8BVYqgC+vDIe4weFq12dwtEEjJi0h+CBSg7z2GLo+WW4YlOgUbHwK/QTaFpqrhGSeQlH34aCwxsPnU3RK8vsDajrbnQPL/1p+ORvxv8uaEYCLIb0cv/6CJg7CHpKs6yLR4o8znBAkEA7cPmWaZAXHNVUP11VwhSR8+GJQo9xYMnZI2D04/w8DNsPSauDr9ZeJc7w5fvkaZZPCARR/gmbrs7AL5NpT5QpwJBALm8pJ3ld+2mIzcvd+zXnQP/0Iz+2VCykE25y6u66bOD541HP0D3rGNho/JV4BPgnwa0nRx2aWkyc9bjDuipTaECQQDSzk/byHVkArXwGukAg1ZAaRSsnonqJsC0fGwXFZYvwcgD59mHJcy0CJJqdrlnz69qiZwIzVF19/b2T8QT8E4dAkBDhlOKm+wX1/ihjX5Z+qE43P3i5Jv4/JH9z/g9vLxN6Tx7XlWetuxTTSIfbh0C3PyzoWIlAN+dwRvgGbhH2ZVBAkB+XCVH/XwrsQbewvyflwqZI1AWfSvpgakCPQ/PYtlfPV/zgFby/RTJchypM28dnQLnZByBM0Av+qTQ1eu+kLW9",
                "MIICWTCCAcKgAwIBAgIIYaNGLiakjGYwDQYJKoZIhvcNAQEFBQAwPzERMA8GA1UEAwwIRGVtb0NBMTAxHTAbBgNVBAoMFERlbW8gT3JnYW5pemF0aW9uIDEwMQswCQYDVQQGEwJTRTAeFw0xMDA0MjExNDE4NTdaFw0xMjA0MjAxNDE4NTdaMB4xHDAaBgNVBAMME3Rlc3Rfa2V5dXNhZ2VsaW1pdDEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKyBxjgYz+1mXW4FW8OtRc7MILWWIZ7FVuGUbJD2HGG41xTux3+cwVgunPwvr2/cOAL3YBBb8xy7T/aifm3CQGcOlbxXGZy4BGzxwsF0lVRSLGNvziesrOhjgAF/4py6b045FEswqAdvLOMmBmmV7+7++6Y7Izg2KQ8+FuVAsfQHAgMBAAGjfzB9MB0GA1UdDgQWBBQS/S/ocFePvX3Z8+WC7rWcSldHXDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFIzRpWLTLadZLpAZR2z1RSqKlERuMA4GA1UdDwEB/wQEAwIF4DAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwDQYJKoZIhvcNAQEFBQADgYEATgFdJtJzSHpeSl/tXVUbH8uSBka4pmhdNycqpim5slZnYAvAJWUjeJh07+gM7z7VWldn8Y3p1leJ9TWHNIaIbzI7OAJWr0pnaOXVL2Bj1kf6x/xJwITIPfOw+Oiq97IMPHlnTSblravBlmpc0GZXM3xCUSvKDQ/IOhWGb/caSG0=;MIICXjCCAcegAwIBAgIIVfqFvbhubAgwDQYJKoZIhvcNAQEFBQAwPzERMA8GA1UEAwwIRGVtb0NBMTAxHTAbBgNVBAoMFERlbW8gT3JnYW5pemF0aW9uIDEwMQswCQYDVQQGEwJTRTAeFw0xMDA0MDMyMjE4NDRaFw0yMDA0MDIyMjE4NDRaMD8xETAPBgNVBAMMCERlbW9DQTEwMR0wGwYDVQQKDBREZW1vIE9yZ2FuaXphdGlvbiAxMDELMAkGA1UEBhMCU0UwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ1J0yCi7uzd3Qhyxt6IJ5UOdrjbrZfEKts2sNOfFDpCRJUrUx0nHb+rY5/hvQXEDqz/apHoHq+RX+QOaYSOMDsMRb/O/uNkyitk1i8zSj2CMp+ts7CEG8PomzbaQA57haZ5tA9ppNJLx9+ukF1CYxCDLLKq0H9rB/JtzwfRuXmRAgMBAAGjYzBhMB0GA1UdDgQWBBSM0aVi0y2nWS6QGUds9UUqipREbjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFIzRpWLTLadZLpAZR2z1RSqKlERuMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQUFAAOBgQA/93lyqxAqcbxRpW5AUSle4N+ikuBAWcL/JHUijMRi//OaDOOCupHnm3lsWfzUfOmUmm4mV80L3kWsws+6yIHaj9UpFxFlGpEbB91rHLw7Oc9yMraiwM6r3RqEhVxZNuam1AnUzeSTFu4X9i3AseUD4xBoxUXHWeqmWTHeXH42Pw==");
        workerSession.setWorkerProperty(WORKERID_1, "KEYUSAGELIMIT",
                String.valueOf(LIMIT));
        workerSession.reloadConfiguration(WORKERID_1);
    }

    /**
     * Do signings up to KEYUSAGELIMIT and then check that the next signing
     * fails.
     *
     * Assumption 1: The database or atleast the table KeyUsageCounter needs to
     * be cleared.
     * Assumption 2: The configured key (test_keyusagelimit1.p12) is not used by
     * any other tests.
     *
     * @throws Exception in case of exception
     */
    public void test01Limit() throws Exception {

        // Do a number of signings LIMIT
        try {
            for (int i = 0; i < LIMIT; i++) {
                LOG.debug("Signing " + i);
                doSign();
            }
        } catch (CryptoTokenOfflineException ex) {
            fail(ex.getMessage());
        }

        try {
            doSign();
            fail("Should have failed now");

        } catch (CryptoTokenOfflineException ok) {
        }
    }

    public void test02NoIncreaseWhenOffline() throws Exception {

        // ASSUMPTION: Key usages is now 10

        // Increase key usage limit so we should be able to do two more signings
        workerSession.setWorkerProperty(WORKERID_1, "KEYUSAGELIMIT",
                String.valueOf(LIMIT + 2));
        workerSession.reloadConfiguration(WORKERID_1);

        // Do one signing just to see that it works
        doSign();

        // Make the signer offline and do one signing that should not increase
        //counter, which means that after activating it again we should be able
        //to do one more signing
        workerSession.deactivateSigner(WORKERID_1);
        doSignOffline();

        // Should be able to do one signing now
        workerSession.activateSigner(WORKERID_1, "foo123");
        doSign();
    }

    /** Do a dummy sign. */
    private void doSign() throws Exception {

        final RequestContext context = new RequestContext();
        final GenericSignRequest request = new GenericSignRequest(1,
                "<root/>".getBytes());
        GenericSignResponse res;
        // Send request to dispatcher
        res = (GenericSignResponse) workerSession.process(WORKERID_1,
                request, context);
        Certificate cert = res.getSignerCertificate();
        assertNotNull(cert);
    }

    /** Do a dummy sign and expect failure. */
    private void doSignOffline() throws Exception {

        try {
            final RequestContext context = new RequestContext();
            final GenericSignRequest request = new GenericSignRequest(1,
                    "<root/>".getBytes());
            // Send request to dispatcher
            workerSession.process(WORKERID_1,
                    request, context);
        } catch (CryptoTokenOfflineException ok) {
            // OK
        } catch (Exception ex) {
            LOG.error("Signer offline but other exception", ex);
            fail("Signer offline but other exception: " + ex.getMessage());
        }
    }

    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKERID_1);
    }
}
