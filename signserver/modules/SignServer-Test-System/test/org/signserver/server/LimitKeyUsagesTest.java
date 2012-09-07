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
                "MIIEoDCCAoigAwIBAgIIOM0BlA53koswDQYJKoZIhvcNAQELBQAwTTEXMBUGA1UEAwwORFNTIFJvb3QgQ0EgMTAxEDAOBgNVBAsMB1Rlc3RpbmcxEzARBgNVBAoMClNpZ25TZXJ2ZXIxCzAJBgNVBAYTAlNFMB4XDTExMTEwNDA2MDcxNVoXDTIxMTEwNDA2MDcxNVowUjEcMBoGA1UEAwwTdGVzdF9rZXl1c2FnZWxpbWl0MTEQMA4GA1UECwwHVGVzdGluZzETMBEGA1UECgwKU2lnblNlcnZlcjELMAkGA1UEBhMCU0UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkmfrPNs6C9uAIOYltwytmzdJm6PwpCdCiCdNvtuqpsSjhbqyCehSUjjsqyfAFtbyIuen38YPmexO8LUAT3ooinJya1BJ1BUX2IGYX9Vz8psVVik+TioAVFWpZMkQAGSt8Ywt7x4qu7/Fn+unR95lBfiFJNm4ODaak59UGtceZKvJokUDJCSb6KNh0iI3H/GxDRf5tUfRVHReaqVVZfYZgI/XVM/CMjjN6WNEc8UzBXOZ1IZzPcs/1BkrXcvOPej/6d2DOoFR153gJ+LoRRx5YEUuWw/qZ6UPSNl9gkyG/vApIFlnTAvM4QvqhWGhGFnVusVXgSXgRDOs6ta7yhxXrAgMBAAGjfzB9MB0GA1UdDgQWBBQ217GiTEGjZPrU+TmRoqFOPovkQjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFCB6Id7orbsCqPtxWKQJYrnYWAWiMA4GA1UdDwEB/wQEAwIF4DAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwDQYJKoZIhvcNAQELBQADggIBABHhLDcjhfWyACzP7oxOKO0Cvdwb9CZiPSoGCSbbO1LuBLZ9raGL1ZSBaxaHyTcifMz7UW5daGMY5N5XLswC2NrXSkoN/ijZFlz64JLIFe/eI+IqEFTHxHFZIFWHgf/KHCeX1nC89UqGUmu64/daZIPbh96EfEZla9/KB7RwC4JSDlniisXuqnQ3rtP4Zxl9PjapZ307gxHFbtCXVYeZ0CEkanCZhtom13d1IbKvTE1jW/ey1zRR2soGl/DZ6G7Kz9KOSWmkKMls5LyyU8QUctnzKy+8IreDDu7toyyvWRGtoSfTrlvcWwojdSFXyBYQmpGwg7r72Qkxl7BLQ48wBEnAQdIb+S4QmYslrDZ7tKtrvpRNFS64XJt5vAlSxhwTHWcIQEtylSFzw3W6uS6vCshaaen0nrMNPs2C0BLYCKuYdWAbTUfJptB3pi8M4S2QBUGrDJl1yaZe91/X8+HZhvbwLnE+QK+8MLQAyzFOR4pH126B/3YSDmq+Wy1lEylQjN3bFp8hiZPCjX4ZVEcA6bTEZFZq13FZUoo7kI3W3M5+cPV+zm7wYj+3kVCkpz6N1Z+L7V+DuhnBxtCkZilb9dlkQqQkaWL5T7KPgvPbLbkYx5bV5mjTJlGYcZejJJsQ/lb6yelAxflsMW5Jp2n6Ex+CLuxesMM5S0X4Fou9s6a8;MIICXjCCAcegAwIBAgIIVfqFvbhubAgwDQYJKoZIhvcNAQEFBQAwPzERMA8GA1UEAwwIRGVtb0NBMTAxHTAbBgNVBAoMFERlbW8gT3JnYW5pemF0aW9uIDEwMQswCQYDVQQGEwJTRTAeFw0xMDA0MDMyMjE4NDRaFw0yMDA0MDIyMjE4NDRaMD8xETAPBgNVBAMMCERlbW9DQTEwMR0wGwYDVQQKDBREZW1vIE9yZ2FuaXphdGlvbiAxMDELMAkGA1UEBhMCU0UwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ1J0yCi7uzd3Qhyxt6IJ5UOdrjbrZfEKts2sNOfFDpCRJUrUx0nHb+rY5/hvQXEDqz/apHoHq+RX+QOaYSOMDsMRb/O/uNkyitk1i8zSj2CMp+ts7CEG8PomzbaQA57haZ5tA9ppNJLx9+ukF1CYxCDLLKq0H9rB/JtzwfRuXmRAgMBAAGjYzBhMB0GA1UdDgQWBBSM0aVi0y2nWS6QGUds9UUqipREbjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFIzRpWLTLadZLpAZR2z1RSqKlERuMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQUFAAOBgQA/93lyqxAqcbxRpW5AUSle4N+ikuBAWcL/JHUijMRi//OaDOOCupHnm3lsWfzUfOmUmm4mV80L3kWsws+6yIHaj9UpFxFlGpEbB91rHLw7Oc9yMraiwM6r3RqEhVxZNuam1AnUzeSTFu4X9i3AseUD4xBoxUXHWeqmWTHeXH42Pw==");
        workerSession.reloadConfiguration(WORKERID_1);
    }

    /**
     * Do signings up to KEYUSAGELIMIT and then check that the next signing
     * fails.
     *
     * Assumption: The configured key (test_keyusagelimit1.p12) is not used by
     * any other tests.
     *
     * @throws Exception in case of exception
     */
    public void test01Limit() throws Exception {

        final long oldValue = workerSession.getKeyUsageCounterValue(WORKERID_1);
        workerSession.setWorkerProperty(WORKERID_1, "KEYUSAGELIMIT",
                String.valueOf(oldValue + LIMIT));
        workerSession.reloadConfiguration(WORKERID_1);
        
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

        // Increase key usage limit so we should be able to do two more signings
        final long oldValue = workerSession.getKeyUsageCounterValue(WORKERID_1);
        workerSession.setWorkerProperty(WORKERID_1, "KEYUSAGELIMIT",
                String.valueOf(oldValue + 2));
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
    
    /**
     * Tests that when the key usage counter is not disabled it will increase 
     * after a signing.
     */
    public void test03IncreaseWhenNotDisabled() throws Exception {
        // Remove any limits just in case
        workerSession.removeWorkerProperty(WORKERID_1, "KEYUSAGELIMIT");
        // Set to not disabled = enabled
        workerSession.setWorkerProperty(WORKERID_1, "DISABLEKEYUSAGECOUNTER", "FaLsE");
        workerSession.reloadConfiguration(WORKERID_1);
        
        final long oldValue = workerSession.getKeyUsageCounterValue(WORKERID_1);
        if (oldValue < 0) {
            throw new Exception("Test case assumes non negative counter value");
        }
        
        doSign();
        
        // Counter should have increased
        final long actual = workerSession.getKeyUsageCounterValue(WORKERID_1);
        assertEquals("counter should have increased", oldValue + 1, actual);
    }
    
    /**
     * Tests that when the key usage counter is disabled and there is no 
     * key usage limit a signing will not increase the counter.
     */
    public void test04NoIncreaseWhenDisabled() throws Exception {
        // Remove any limits just in case
        workerSession.removeWorkerProperty(WORKERID_1, "KEYUSAGELIMIT");
        // Set to be disabled
        workerSession.setWorkerProperty(WORKERID_1, "DISABLEKEYUSAGECOUNTER", "TrUe");
        workerSession.reloadConfiguration(WORKERID_1);
        
        final long oldValue = workerSession.getKeyUsageCounterValue(WORKERID_1);
        if (oldValue < 0) {
            throw new Exception("Test case assumes non negative counter value");
        }
        
        doSign();
        
        // Counter should not have increased
        final long actual = workerSession.getKeyUsageCounterValue(WORKERID_1);
        assertEquals("counter should have increased", oldValue, actual);
    }
    
    /**
     * Tests that when the key usage counter is disabled but there is a limit
     * it will still count. This is actually a configuration error but we want 
     * to treat it the safe way which is to still honor the limit. 
     */
    public void test05IncreaseWhenDisabledButThereIsALimit() throws Exception {
        // Set a limit so we should still to counting
        workerSession.setWorkerProperty(WORKERID_1, "KEYUSAGELIMIT", "100000");
        // Set to disabled
        workerSession.setWorkerProperty(WORKERID_1, "DISABLEKEYUSAGECOUNTER", "TRUE");
        workerSession.reloadConfiguration(WORKERID_1);
        
        final long oldValue = workerSession.getKeyUsageCounterValue(WORKERID_1);
        if (oldValue < 0) {
            throw new Exception("Test case assumes non negative counter value");
        }
        
        doSign();
        
        // Counter should have increased
        final long actual = workerSession.getKeyUsageCounterValue(WORKERID_1);
        assertEquals("counter should have increased", oldValue + 1, actual);
    }
    
    public void test06() throws Exception {
        final long oldValue = workerSession.getKeyUsageCounterValue(WORKERID_1);
        if (oldValue < 0) {
            throw new Exception("Test case assumes non negative counter value");
        }
        
        // Set a limit so we can only do one signing
        workerSession.setWorkerProperty(WORKERID_1, "KEYUSAGELIMIT", String.valueOf(oldValue + 1));
        // Set to disabled
        workerSession.setWorkerProperty(WORKERID_1, "DISABLEKEYUSAGECOUNTER", "TRUE");
        workerSession.reloadConfiguration(WORKERID_1);
        
        // One signing is ok
        doSign();
        
        // Next the signer should be offline
        doSignOffline();
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
