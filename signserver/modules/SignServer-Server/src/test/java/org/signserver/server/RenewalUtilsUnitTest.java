package org.signserver.server;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.EdECKey;

import static org.junit.Assert.*;

/**
 * Unit tests for the RenewalUtils class.
 */
public class RenewalUtilsUnitTest {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(RenewalUtils.class);

    public RenewalUtilsUnitTest() {}

    @BeforeClass
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterClass
    public static void tearDownClass() {}

    @Before
    public void setUp() {}

    @After
    public void tearDown() {}

    @Test
    public void testGetRequestSignatureAlgorithmWithOnlySignatureAlgorithm() {
        LOG.info("testGetRequestSignatureAlgorithmWithOnlySignatureAlgorithm");

        final String expected = "SHA1withRSA";
        final String actual = RenewalUtils.getRequestSignatureAlgorithm("", expected, null);

        assertEquals(expected, actual);
    }

    @Test
    public void testGetRequestSignatureAlgorithmDefaultValue() {
        LOG.info("testGetRequestSignatureAlgorithmDefaultValue");

        final String expected = "SHA512withRSA";
        final String signatureAlgorithm = "NONEwithRSA";
        final String actual = RenewalUtils.getRequestSignatureAlgorithm("", signatureAlgorithm, null);

        assertEquals(expected, actual);
    }

    @Test
    public void testGetRequestSignatureAlgorithmWithRequestSignatureAlgorithm() {
        LOG.info("testGetRequestSignatureAlgorithmWithRequestSignatureAlgorithm");

        final String expected = "Ed25519";
        final String signatureAlgorithm = "SHA512withRSA";
        final String actual = RenewalUtils.getRequestSignatureAlgorithm(expected, signatureAlgorithm, null);
        assertEquals(expected, actual);
    }

    @Test
    public void testGetRequestSignatureAlgorithmSignerCertKeyAlgorithm_JCE() throws CertificateException, IOException, NoSuchProviderException {
        internalGetRequestSignatureAlgorithmSignerCertKeyAlgorithm(null);
    }
    @Test
    public void testGetRequestSignatureAlgorithmSignerCertKeyAlgorithm_BC() throws
            CertificateException, IOException, NoSuchProviderException {
        internalGetRequestSignatureAlgorithmSignerCertKeyAlgorithm("BC");
    }

    private void internalGetRequestSignatureAlgorithmSignerCertKeyAlgorithm(String provider) throws CertificateException, IOException, NoSuchProviderException {
        LOG.info("testGetRequestSignatureAlgorithmSignerCertKeyAlgorithm(" +
                provider + ")");
        final String pem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIBMTCB5KADAgECAgYBhpIxOBkwBQYDK2VwMD8xCzAJBgNVBAYTAlNFMSAwHgYD\n" +
                "VQQHDBdfU2lnblNlcnZlcl9EVU1NWV9DRVJUXzEOMAwGA1UEAxMFRURLRVkwIBcN\n" +
                "MjMwMjI3MDkyNTQ0WhgPMjA1MzAyMTkwOTM1NDRaMD8xCzAJBgNVBAYTAlNFMSAw\n" +
                "HgYDVQQHDBdfU2lnblNlcnZlcl9EVU1NWV9DRVJUXzEOMAwGA1UEAxMFRURLRVkw\n" +
                "KjAFBgMrZXADIQDVLtaT5KioM4ry9BoQz2Y3kSSogPbipCLw5AL+wGczazAFBgMr\n" +
                "ZXADQQCgBA0P/Afe82/ilewVhstsf46ft4wmTM6SUXadBCYsdb5BRciouwtyUOuv\n" +
                "NW8E2ib9CqgiThB8Kz4x5OZHlj4G\n" +
                "-----END CERTIFICATE-----\n";

        Certificate cert;
        try (InputStream inputStream = new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII))) {
            if (provider == null) {
                cert = CertificateFactory.getInstance("X509").generateCertificate(inputStream);
            } else {
                cert = CertificateFactory.getInstance("X509", provider).generateCertificate(inputStream);
            }
        }

        final String expected = "Ed25519";
        final String actual = RenewalUtils.getRequestSignatureAlgorithm("", "", cert);

        assertEquals(expected, actual);
    }
}
