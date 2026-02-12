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
package org.signserver.client.cli;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.Test;
import org.signserver.cli.CommandLineInterface;
import org.signserver.common.AbstractCertReqData;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ISignerCertReqInfo;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerIdentifier;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertExt;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.ejb.interfaces.WorkerSession;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests for the timestamp command of Client CLI.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class TimeStampCommandTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(TimeStampCommandTest.class);

    private final CLITestHelper cli = getClientCLI();

    private static final String SAMPLE_QUERY_FILE = "res/test/sample.tsq";
    private static final String SAMPLE_QUERY_CERTREQ_FILE = "res/test/sample-certreq.tsq";
    private static final String SAMPLE_RESPONSE_FILE = "res/test/sample.tsr";
    private static final String SAMPLE_RESPONSE_CERTREQ_FILE = "res/test/sample-certreq.tsr";

    private final WorkerSession workerSession = getWorkerSession();

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        addTimeStampSigner(getSignerIdTimeStampSigner1(), getSignerNameTimeStampSigner1(), true);
        workerSession.setWorkerProperty(getSignerIdTimeStampSigner1(), "DEFAULTTSAPOLICYOID", "1.2.13.1");
        workerSession.removeWorkerProperty(getSignerIdTimeStampSigner1(), "ACCEPTANYPOLICY");
        workerSession.setWorkerProperty(getSignerIdTimeStampSigner1(), "ACCEPTEDPOLICIES", "1.2.13.1;1.2.13.9");
        workerSession.reloadConfiguration(getSignerIdTimeStampSigner1());
    }

    @Test
    public void test01missingArguments() throws Exception {
        assertEquals("No arguments", CommandLineInterface.RETURN_INVALID_ARGUMENTS,
                cli.execute("timestamp"));
    }

    /**
     * Tests getting a timestamp.
     */
    @Test
    public void test02requestATimestamp() throws Exception {
        File responseFile = File.createTempFile("signserver-" + this.getClass().getName() + "-response2-", null);
        responseFile.deleteOnExit();
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-instr", "Any text we want to have a timestamp for...123", "-outrep", responseFile.getAbsolutePath(), "-url", "http://localhost:8080/signserver/tsa?workerId=" + getSignerIdTimeStampSigner1()));
        try (InputStream in = new FileInputStream(responseFile)) {
            TimeStampResponse res = new TimeStampResponse(in);
            assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
        }
    }

    /**
     * This test generates a composite key-pair (MLDSA87-RSA3072-PSS-SHA512) and stores it in a keystore, then
     * uses the key-pair to generate a CSR. A CA is created to sign the CSR and issue a signer certificate with
     * the timestamping extended key usage. The certificate chain (CA + signer certificate) is then installed in the
     * TimestampSigner. The test then timestamps a string of text and saves the response to disk, which is then Base64
     * encoded and rewritten to disk. Since this test specifies the -cafile flag, the test will try build a certificate chain
     * with the provided trusted PEM encoded certificate and the certificates available in the timestamp token, and then
     * tries to validate the trust.
     * @throws Exception
     */
    @Test
    public void test03compositeTimestampVerifyUsingCafile() throws Exception {
        final int timestampSignerId = 9000;
        final int keystoreId = 9001;
        final KeyStore ks = KeyStore.getInstance("pkcs12");
        final File keystore = File.createTempFile("test03compositeTimestampVerifyUsingCafile", ".p12");
        final File responseFile = File.createTempFile("signserver-" + this.getClass().getName() + "-response3-", ".base64");
        final File pemFile = File.createTempFile("test03compositeTimestampVerifyUsingCafile", ".pem");
        keystore.deleteOnExit();
        responseFile.deleteOnExit();
        pemFile.deleteOnExit();

        try {
            char[] password = "foo123".toCharArray();
            ks.load(null, password);

            try (FileOutputStream fos = new FileOutputStream(keystore.getAbsolutePath())) {
                ks.store(fos, password);
            }

            // Create timestamp signer with seperate token
            addTimeStampSignerNoToken(timestampSignerId, "CompositeTimeStampSigner");

            // Create keystore crypto worker
            addKeyStoreCrypto(keystoreId, "CompositeKeyStore", keystore.getAbsolutePath(), "foo123");

            workerSession.generateSignerKey(new WorkerIdentifier(keystoreId),
                    "COMPOSITE",
                    "MLDSA87-RSA3072-PSS-SHA512",
                    "compositekey-COMPOSITE",
                    "foo123".toCharArray());

            workerSession.setWorkerProperty(timestampSignerId, "CRYPTOTOKEN", "CompositeKeyStore");
            workerSession.setWorkerProperty(timestampSignerId, "DEFAULTKEY", "compositekey-COMPOSITE");
            workerSession.setWorkerProperty(timestampSignerId, "SIGNATUREALGORITHM", "MLDSA87-RSA3072-PSS-SHA512");
            workerSession.setWorkerProperty(timestampSignerId, "DISABLEKEYUSAGECOUNTER", "true");
            workerSession.reloadConfiguration(timestampSignerId);

            // CA key-pair generation
            final ASN1ObjectIdentifier compositeOID = IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512;
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance(compositeOID.getId(), "BC");
            final KeyPair compKeyPair = kpg.generateKeyPair();

            // Create CA
            final String caDN = "CN=CA Composite CLI Test";
            long currentTime = System.currentTimeMillis();
            X509CertificateHolder caCertHolder = new CertBuilder()
                    .setSelfSignKeyPair(new KeyPair(compKeyPair.getPublic(), compKeyPair.getPrivate()))
                    .setNotBefore(new Date(currentTime - 120000))
                    .setSignatureAlgorithm("MLDSA87-RSA3072-PSS-SHA512")
                    .setIssuer(caDN)
                    .setSubject(caDN)
                    .addExtension(new CertExt(Extension.basicConstraints, true, new BasicConstraints(true)))
                    .addExtension(new CertExt(Extension.keyUsage, false, new X509KeyUsage(X509KeyUsage.keyCertSign)))
                    .build();

            // Generate CSR
            final ISignerCertReqInfo req
                    = new PKCS10CertReqInfo("MLDSA87-RSA3072-PSS-SHA512", "CN=Composite Timestamp signer" + timestampSignerId, null);
            final AbstractCertReqData reqData
                    = (AbstractCertReqData) workerSession.getCertificateRequest(new WorkerIdentifier(keystoreId), req, false, "compositekey-COMPOSITE");

            // Create signer certificate with timestamping key usage (critical). This signer certificate will be signed
            // by the CA. In the end, we will include the entire chain for our timestamp signer.
            final PKCS10CertificationRequest csr = new PKCS10CertificationRequest(reqData.toBinaryForm());

            final SubjectPublicKeyInfo subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();
            final PublicKey signerPublicKey = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(subjectPublicKeyInfo);

            final X509CertificateHolder signerCertHolder = new CertBuilder()
                    .setNotBefore(new Date(currentTime - 120000))
                    .setSignatureAlgorithm("MLDSA87-RSA3072-PSS-SHA512")
                    .setIssuer(caDN)
                    .setSubject(csr.getSubject())
                    .setIssuerPrivateKey(compKeyPair.getPrivate())
                    .setSubjectPublicKey(signerPublicKey)
                    .addExtension(new CertExt(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)))
                    .build();

            // Certificate chain containing CA and signer certificate
            final List<byte[]> chain =
                    Arrays.asList(
                            new JcaX509CertificateConverter().getCertificate(signerCertHolder).getEncoded(),
                            new JcaX509CertificateConverter().getCertificate(caCertHolder).getEncoded()
                    );

            // Upload certs to timestamp signer
            workerSession.uploadSignerCertificate(timestampSignerId, chain.get(0), GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.uploadSignerCertificateChain(timestampSignerId, chain, GlobalConfiguration.SCOPE_GLOBAL);
            workerSession.reloadConfiguration(timestampSignerId);

            // Timestamp a string and store the TSA reply on disk.
            assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp",
                    "-instr", "test03compositeTimestampVerifyUsingCafile",
                    "-outrep", responseFile.getAbsolutePath(),
                    "-certreq",
                    "-url", "https://" + getHTTPHost() + ":" + getPublicHTTPSPort() + "/signserver/tsa?workerId=" + timestampSignerId,
                    "-truststore", getTestUtils().getTruststoreFile().getAbsolutePath(),
                    "-truststorepwd", getTestUtils().getTrustStorePassword()));

            // Write base64 string to new file
            String base64DataString = Base64.toBase64String(Files.readAllBytes(responseFile.toPath()));
            try (FileOutputStream fos = new FileOutputStream(responseFile)) {
               fos.write(base64DataString.getBytes());
            }

            // Write pem string to test03compositeTimestampVerifyUsingCafile.pem
            final FileWriter fwout = new FileWriter(pemFile.getAbsolutePath());
            try (JcaPEMWriter writer = new JcaPEMWriter(fwout)) {
                writer.writeObject(caCertHolder);
            }

            assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp",
                    "-verify",
                    "-base64",
                    "-inrep", responseFile.getAbsolutePath(),
                    "-cafile", pemFile.getAbsolutePath()
            ));

            String out = new String(cli.getOut().toByteArray());
            assertTrue("Certificate chain did not properly validate: " + out, out.contains("Successfully validated chain"));
            assertTrue("Could not properly verify timestamp signature: " + out, out.contains("Token was validated successfully"));

        } finally {
            removeWorker(timestampSignerId);
            removeWorker(keystoreId);
        }
    }

    /**
     *
     * This test uses the exising ts00003 key and certificate that is available in dss10_keystore.p12. The test then
     * timestamps a string of text and saves the response to disk, which is then Base64 encoded and rewritten to disk. Since
     * this test specifies the -signerfile flag, the test will validate the timestamp token by making sure that the
     * timestamp token is signed using the provided PEM encoded signer certificate. Validating the timestamp token
     * also verifies that the certificate has the KeyPurposeId.id_kp_timeStamping ExtendedKeyUsageExtension
     * @throws Exception
     */
    @Test
    public void test03TimestampVerifyUsingSignerfileBase64() throws Exception {
        final int timestampSignerId = 9000;
        final int keystoreId = 9001;
        final KeyStore ks = KeyStore.getInstance("pkcs12");
        final File keystore = new File(getSignServerHome() + "/res/test/dss10/dss10_keystore.p12");
        final File responseFile = File.createTempFile("signserver-" + this.getClass().getName() + "-response3-", ".base64");
        final File pemFile = File.createTempFile("test03TimestampVerifyUsingSignerfile", ".pem");
        responseFile.deleteOnExit();
        pemFile.deleteOnExit();

        try {
            try (FileInputStream fis = new FileInputStream(keystore.getAbsolutePath())) {
                ks.load(fis, "foo123".toCharArray());
            }

            final X509Certificate signerCert = (X509Certificate) ks.getCertificate("ts00003");

            // Create timestamp signer with seperate token
            final String signerName = "TimeStampSigner-" + System.currentTimeMillis();
            addTimeStampSignerNoToken(timestampSignerId, signerName);

            // Create keystore crypto worker
            final String cryptoName = "KeyStoreCrypto-" + System.currentTimeMillis();
            addKeyStoreCrypto(keystoreId, cryptoName, keystore.getAbsolutePath(), "foo123");

            workerSession.setWorkerProperty(timestampSignerId, "CRYPTOTOKEN", cryptoName);
            workerSession.setWorkerProperty(timestampSignerId, "DEFAULTKEY", "ts00003");
            workerSession.setWorkerProperty(timestampSignerId, "SIGNATUREALGORITHM", "SHA256withRSA");
            workerSession.reloadConfiguration(timestampSignerId);

            // Timestamp a string and store the TSA reply on disk.
            assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp",
                    "-instr", "test03TimestampVerifyUsingSignerfile",
                    "-outrep", responseFile.getAbsolutePath(),
                    "-certreq",
                    "-url", "https://" + getHTTPHost() + ":" + getPublicHTTPSPort() + "/signserver/tsa?workerId=" + timestampSignerId,
                    "-truststore", getTestUtils().getTruststoreFile().getAbsolutePath(),
                    "-truststorepwd", getTestUtils().getTrustStorePassword()));

            // Write base64 string to new file
            String base64DataString = Base64.toBase64String(Files.readAllBytes(responseFile.toPath()));
            try (FileOutputStream fos = new FileOutputStream(responseFile)) {
                fos.write(base64DataString.getBytes());
            }

            // Write pem string to test03TimestampVerifyUsingSignerfile.pem
            try (FileWriter fwout = new FileWriter(pemFile.getAbsolutePath()); JcaPEMWriter writer = new JcaPEMWriter(fwout)) {
                writer.writeObject(signerCert);
            }

            assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp",
                    "-verify",
                    "-base64",
                    "-inrep", responseFile.getAbsolutePath(),
                    "-signerfile", pemFile.getAbsolutePath()
            ));

            String out = new String(cli.getOut().toByteArray());
            assertTrue("Could not properly verify timestamp signature: " + out, out.contains("Token was validated successfully"));
        } finally {
            removeWorker(timestampSignerId);
            removeWorker(keystoreId);
        }
    }

    /**
     *
     * This test uses the exising ts00003 key and certificate that is available in dss10_keystore.p12. The test then
     * timestamps a string of text and saves the response to disk. Since this test specifies the -signerfile flag, the
     * test will validate the timestamp token by making sure that the timestamp token is signed using the
     * provided PEM encoded signer certificate. Validating the timestamp token also verifies that the certificate has
     * the KeyPurposeId.id_kp_timeStamping ExtendedKeyUsageExtension
     * @throws Exception
     */
    @Test
    public void test03TimestampVerifyUsingSignerfile() throws Exception {
        final int timestampSignerId = 9000;
        final int keystoreId = 9001;
        final KeyStore ks = KeyStore.getInstance("pkcs12");
        final File keystore = new File(getSignServerHome() + "/res/test/dss10/dss10_keystore.p12");
        final File responseFile = File.createTempFile("signserver-" + this.getClass().getName() + "-response3-", ".base64");
        final File pemFile = File.createTempFile("test03TimestampVerifyUsingSignerfile", ".pem");
        responseFile.deleteOnExit();
        pemFile.deleteOnExit();

        try {
            try (FileInputStream fis = new FileInputStream(keystore.getAbsolutePath())) {
                ks.load(fis, "foo123".toCharArray());
            }

            final X509Certificate signerCert = (X509Certificate) ks.getCertificate("ts00003");

            // Create timestamp signer with seperate token
            final String signerName = "TimeStampSigner-" + System.currentTimeMillis();
            addTimeStampSignerNoToken(timestampSignerId, signerName);

            // Create keystore crypto worker
            final String cryptoName = "KeyStoreCrypto-" + System.currentTimeMillis();
            addKeyStoreCrypto(keystoreId, cryptoName, keystore.getAbsolutePath(), "foo123");

            workerSession.setWorkerProperty(timestampSignerId, "CRYPTOTOKEN", cryptoName);
            workerSession.setWorkerProperty(timestampSignerId, "DEFAULTKEY", "ts00003");
            workerSession.setWorkerProperty(timestampSignerId, "SIGNATUREALGORITHM", "SHA256withRSA");
            workerSession.reloadConfiguration(timestampSignerId);

            // Timestamp a string and store the TSA reply on disk.
            assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp",
                    "-instr", "test03TimestampVerifyUsingSignerfile",
                    "-outrep", responseFile.getAbsolutePath(),
                    "-certreq",
                    "-url", "https://" + getHTTPHost() + ":" + getPublicHTTPSPort() + "/signserver/tsa?workerId=" + timestampSignerId,
                    "-truststore", getTestUtils().getTruststoreFile().getAbsolutePath(),
                    "-truststorepwd", getTestUtils().getTrustStorePassword()));

            // Write pem string to test03TimestampVerifyUsingSignerfile.pem
            try (FileWriter fwout = new FileWriter(pemFile.getAbsolutePath()); JcaPEMWriter writer = new JcaPEMWriter(fwout)) {
                writer.writeObject(signerCert);
            }

            assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp",
                    "-verify",
                    "-inrep", responseFile.getAbsolutePath(),
                    "-signerfile", pemFile.getAbsolutePath()
            ));

            String out = new String(cli.getOut().toByteArray());
            assertTrue("Could not properly verify timestamp signature: " + out, out.contains("Token was validated successfully"));
        } finally {
            removeWorker(timestampSignerId);
            removeWorker(keystoreId);
        }
    }

    @Test
    public void test04VerifyUsingCafileOnTimestampResponseWithoutCertreq() throws Exception {
        final File requestCertFile = new File(getSignServerHome(), SAMPLE_RESPONSE_FILE);

        assertEquals(CommandLineInterface.RETURN_ERROR, cli.execute("timestamp",
                "-verify",
                "-inrep", requestCertFile.getAbsolutePath(),
                "-cafile", getSignServerHome().getAbsolutePath() + "/res/test/dss10/DSSRootCA10.cacert.pem"));
        String out = new String(cli.getErr().toByteArray());
        assertTrue("Timestamp token should not contain any certificates: " + out,
                out.contains("No signing certificate found in the timestamp token"));
    }

    /**
     * Test that not specifying either -signerfile or -cafile when verifying timestamp response is not allowed.
     * @throws Exception
     */
    @Test
    public void test04VerifyWithoutSignerfileAndCafileShouldFail() throws Exception {
        final File requestCertFile = new File(getSignServerHome(), SAMPLE_QUERY_CERTREQ_FILE);

        assertEquals(CommandLineInterface.RETURN_INVALID_ARGUMENTS, cli.execute("timestamp",
                "-verify",
                "-inrep", requestCertFile.getAbsolutePath()));
        String out = new String(cli.getErr().toByteArray());
        assertTrue("Should require -signerfile or -cafile: " + out, out.contains("Need to specify either -signerfile or -cafile"));
    }

    /**
     * Testing that specifying both -signerfile and -cafile is not allowed.
     * @throws Exception
     */
    @Test
    public void test04VerifyWithSignerfileAndCafileShouldFail() throws Exception {
        final File requestCertFile = new File(getSignServerHome(), SAMPLE_QUERY_CERTREQ_FILE);

        assertEquals(CommandLineInterface.RETURN_INVALID_ARGUMENTS, cli.execute("timestamp",
                "-verify",
                "-inrep", requestCertFile.getAbsolutePath(),
                "-signerfile", "no_need_to_point_to_pem",
                "-cafile", "no_need_to_point_to_pem"));
        String out = new String(cli.getErr().toByteArray());
        assertTrue("Should require -signerfile or -cafile: " + out, out.contains("Need to specify either -signerfile or -cafile"));
    }

    /**
     * Test that verifying a timestamp response without the -inrep flag is not allowed.
     * @throws Exception
     */
    @Test
    public void test04VerifyWithoutInrepShouldFail() throws Exception {
        assertEquals(CommandLineInterface.RETURN_INVALID_ARGUMENTS, cli.execute("timestamp",
                "-verify"));
        String out = new String(cli.getErr().toByteArray());
        assertTrue("Should require -inrep: " + out, out.contains("Needs an inrep!"));
    }

    /**
     * Test that providing a PEM not containing a certificate is not allowed when using the -signerfile flag.
     * @throws Exception
     */
    @Test
    public void test05VerifyWithSignerfileUsingEmptyPemShouldFail() throws Exception {
        final File pemFile = File.createTempFile("test08VerifyWithSignfileUsingEmptyPem", ".pem");
        final File responseFile = File.createTempFile("signserver-" + this.getClass().getName() + "-response5-", ".base64");
        final File sampleResponseFile = new File(getSignServerHome(), SAMPLE_RESPONSE_CERTREQ_FILE);

        pemFile.deleteOnExit();

        // Write base64 string to new file
        String base64DataString = Base64.toBase64String(Files.readAllBytes(sampleResponseFile.toPath()));
        try (FileOutputStream fos = new FileOutputStream(responseFile)) {
            fos.write(base64DataString.getBytes());
        }

        assertEquals(CommandLineInterface.RETURN_ERROR, cli.execute("timestamp",
                "-verify",
                "-base64",
                "-inrep", responseFile.getAbsolutePath(),
                "-signerfile", pemFile.getAbsolutePath()));
        String out = new String(cli.getErr().toByteArray());
        assertTrue("Should fail because -signfile does not contain a certificate: " + out,
                out.contains("No certificate found in file:"));
    }

    /**
     * Test that providing a PEM not containing a certificate is not allowed when using the -cafile flag.
     * @throws Exception
     */
    @Test
    public void test05VerifyWithCafileUsingEmptyPemShouldFail() throws Exception {
        final File pemFile = File.createTempFile("test08VerifyWithCafileUsingEmptyPem", ".pem");
        final File responseFile = File.createTempFile("signserver-" + this.getClass().getName() + "-response5-", ".base64");
        final File sampleResponseFile = new File(getSignServerHome(), SAMPLE_RESPONSE_CERTREQ_FILE);

        pemFile.deleteOnExit();

        // Write base64 string to new file
        String base64DataString = Base64.toBase64String(Files.readAllBytes(sampleResponseFile.toPath()));
        try (FileOutputStream fos = new FileOutputStream(responseFile)) {
            fos.write(base64DataString.getBytes());
        }

        assertEquals(CommandLineInterface.RETURN_ERROR, cli.execute("timestamp",
                "-verify",
                "-base64",
                "-inrep", responseFile.getAbsolutePath(),
                "-cafile", pemFile.getAbsolutePath()));

        String out = new String(cli.getErr().toByteArray());
        assertTrue("Should fail because -cafile does not contain a certificate: " + out,
                out.contains("No certificate found in file:"));
    }

    /**
     * Tests getting a timestamp over HTTPS (port 8442).
     */
    @Test
    public void test02requestATimestampOverHTTPS() throws Exception {
        File responseFile = File.createTempFile("signserver-" + this.getClass().getName() + "-response2-", null);
        responseFile.deleteOnExit();
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-instr", "Any text we want to have a timestamp for...123", "-outrep", responseFile.getAbsolutePath(),
                "-url", "https://" + getHTTPHost() + ":" + getPublicHTTPSPort() + "/signserver/tsa?workerId=" + getSignerIdTimeStampSigner1(),
                "-truststore", getTestUtils().getTruststoreFile().getAbsolutePath(), "-truststorepwd", getTestUtils().getTrustStorePassword()));
        try (InputStream in = new FileInputStream(responseFile)) {
            TimeStampResponse res = new TimeStampResponse(in);
            assertEquals("token granted", PKIStatus.GRANTED, res.getStatus());
        }
    }

    /**
     * Tests the CLI without having the BC provider installed as the CLI
     * should install it itself.
     */
    @Test
    public void test03withoutBCalreadyInstalled() throws Exception {
        Security.removeProvider("BC");
        test02requestATimestamp();
    }

    /**
     * Tests printing requests.
     */
    @Test
    public void test04printRequest() throws Exception {
        LOG.info("test04printRequest");
        final File requestFile = new File(getSignServerHome(), SAMPLE_QUERY_FILE);
        final File requestCertFile = new File(getSignServerHome(), SAMPLE_QUERY_CERTREQ_FILE);

        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-print", "-inreq", requestFile.getAbsolutePath()));
        String out = new String(cli.getOut().toByteArray());
        assertTrue("No request in: " + out, out.contains("Time-stamp request") && out.contains("}"));

        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-print", "-inreq", requestCertFile.getAbsolutePath()));
        out = new String(cli.getOut().toByteArray());
        assertTrue("No request in: " + out, out.contains("Time-stamp request") && out.contains("}"));
    }

    /**
     * Tests printing responses.
     */
    @Test
    public void test05printResponses() throws Exception {
        LOG.info("test05printResponses");
        final File requestFile = new File(getSignServerHome(), SAMPLE_RESPONSE_FILE);
        final File requestCertFile = new File(getSignServerHome(), SAMPLE_RESPONSE_CERTREQ_FILE);

        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-print", "-inrep", requestFile.getAbsolutePath()));
        String out = new String(cli.getOut().toByteArray());
        assertTrue("No response in: " + out, out.contains("Time-stamp response") && out.contains("}"));

        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-print", "-inrep", requestCertFile.getAbsolutePath()));
        out = new String(cli.getOut().toByteArray());
        assertTrue("No response in: " + out, out.contains("Time-stamp response") && out.contains("}"));
    }

    /**
     * Test that trying to use a URL pointing to a non-existing worker will
     * print out the HTTP error code and message on the error stream.
     */
    @Test
    public void test06unknownWorker() throws Exception {
        assertEquals(CommandLineInterface.RETURN_ERROR,
                cli.execute("timestamp", "-instr",
                            "Any text we want to have a timestamp for...123",
                            "-url", "http://localhost:8080/signserver/tsa?workerName=_nonExisting"));
        final String err = new String(cli.getErr().toByteArray());
        // JBoss seems to rewrite HTTP error message, so check both variants
        assertTrue("Prints HTTP error 404: " + err,
                err.contains("Failure: HTTP error: 404: Not Found") ||
                err.contains("Failure: HTTP error: 404: Worker Not Found"));
    }

    /**
     * Tests that command fails when invalid digest algorithm is provided.
     */
    @Test
    public void test07InvalidDigestAlgorithm() throws Exception {
        try {
            cli.execute("timestamp", "-instr",
                    "Any text we want to have a timestamp for...123",
                    "-url", "http://localhost:8080/signserver/tsa?workerId=" + getSignerIdTimeStampSigner1(), "-digestalgorithm", "invalidDigestAlgorithm");
            fail("should fail");
        } catch (UnexpectedCommandFailureException e) {
            assertTrue("Should throw exception: " + e.getMessage(), e.getMessage().contains("Invalid digest algorithm"));
        }
    }

    /**
     * Tests that command works when valid digest algorithm is provided.
     */
    @Test
    public void test08ValidDigestAlgorithm() throws Exception {
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-instr",
                "Any text we want to have a timestamp for...123",
                "-url", "http://localhost:8080/signserver/tsa?workerId=" + getSignerIdTimeStampSigner1(), "-digestalgorithm", "SHA-256"));
    }

    /**
     * Tests that command works when digest algorithm is not provided as default digest algorithm (SHA-256) is used.
     */
    @Test
    public void test09DigestAlgorithmNotSpecified() throws Exception {
        assertEquals(CommandLineInterface.RETURN_SUCCESS, cli.execute("timestamp", "-instr",
                "Any text we want to have a timestamp for...123",
                "-url", "http://localhost:8080/signserver/tsa?workerId=" + getSignerIdTimeStampSigner1()));
    }

    /**
     * Tests that command fails when digest algorithm option name is invalid.
     */
    @Test
    public void test10InvalidDigestAlgorithmOptionName() throws Exception {
        assertEquals("Invalid arguments", CommandLineInterface.RETURN_INVALID_ARGUMENTS, cli.execute("timestamp", "-instr",
                "Any text we want to have a timestamp for...123",
                "-url", "http://localhost:8080/signserver/tsa?workerId=" + getSignerIdTimeStampSigner1(), "-digestAlgorithm", "SHA-256"));
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(getSignerIdTimeStampSigner1());
    }
}
