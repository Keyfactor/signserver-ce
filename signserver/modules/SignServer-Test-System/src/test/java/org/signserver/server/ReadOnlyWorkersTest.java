package org.signserver.server;

import io.restassured.http.Method;
import io.restassured.response.Response;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.json.simple.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.signserver.cli.CommandLineInterface;
import org.signserver.cli.spi.UnexpectedCommandFailureException;
import org.signserver.common.AuthorizedClient;
import org.signserver.common.CertificateMatchingRule;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.MatchIssuerWithType;
import org.signserver.common.MatchSubjectWithType;
import org.signserver.common.NoSuchWorkerException;
import org.signserver.common.ReadOnlyWorkerException;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerExistsException;
import org.signserver.module.cmssigner.PlainSigner;
import org.signserver.server.cryptotokens.KeystoreCryptoToken;
import org.signserver.server.log.AdminInfo;
import org.signserver.test.utils.builders.CertBuilder;
import org.signserver.test.utils.builders.CertBuilderException;
import org.signserver.test.utils.mock.WorkerSessionMock;
import org.signserver.testutils.CLITestHelper;
import org.signserver.testutils.ModulesTestCase;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Test class for ReadOnlyWorkers. This class tests that workers listed as read-only can not be added, deleted or configured using any
 * of the remote interface. Local changes using AdminCLI is allowed.
 */
public class ReadOnlyWorkersTest extends ModulesTestCase {

    private CLITestHelper adminCli = getAdminCLI();
    private WorkerSessionMock mock = new WorkerSessionMock();

    private final int READ_ONLY_WORKER = 80000;

    @Before
    public void resetMock() {
        // Init new WorkerSessionMock before every test method
        mock = new WorkerSessionMock();
        // Set what ID should be read-only for the MockedWorkerSession
        mock.setReadOnlyWorkers(new HashSet<>(Arrays.asList(READ_ONLY_WORKER)));
    }

    /**
     * Test that adding a worker within the read-only range is not allowed using any remote interface.
     *
     * @throws WorkerExistsException
     */
    @Test
    public void testAddWorkerShouldThrowException() throws WorkerExistsException {
        final HashMap<String, String> properties = new HashMap<>();
        properties.put("NAME", "Test");

        Exception exception = null;
        try {
            mock.addWorker(new AdminInfo("testAddWorkerShouldThrowException", null, null, null),
                    READ_ONLY_WORKER, properties);
        } catch (ReadOnlyWorkerException ex) {
            exception = ex;
        }
        assertNotNull("Expected ReadOnlyWorkerException but was null", exception);
        assertEquals("Worker " + READ_ONLY_WORKER + " is read-only", exception.getMessage());
    }

    /**
     * Test that adding a worker within the read-only range is not allowed using the REST interface.
     *
     * @throws Exception
     */
    @Test
    public void testAddWorkerRestShouldReturn405() throws Exception {
        final JSONObject inner = new JSONObject();
        inner.put("NAME", "Test");
        final JSONObject outer = new JSONObject();
        outer.put("properties", inner);

        final Response resp =
                callRest(Method.POST, 405, "", "/workers/" + READ_ONLY_WORKER, outer, getAuthorizedStore());

        assertNotNull(resp);
        assertEquals(405, resp.getStatusCode());
        assertTrue(resp.getBody().asString().contains("Worker ID " + READ_ONLY_WORKER + " is reserved"));
    }

    /**
     * Test that adding a worker via AdminCLI is allowed.
     *
     * @throws IOException
     * @throws UnexpectedCommandFailureException
     */
    @Test
    public void testAddWorkerViaAdminCLIShouldSucceed() throws IOException, UnexpectedCommandFailureException {
        final File workerPropertiesFile = File.createTempFile("testAddWorkerViaAdminCLI-" + System.currentTimeMillis(), ".properties");
        try {
            final Properties properties = new Properties();
            properties.put("WORKER" + READ_ONLY_WORKER + ".NAME", "Test");

            try (FileOutputStream fos = new FileOutputStream(workerPropertiesFile)) {
                properties.store(fos, null);
            }
            assertEquals(CommandLineInterface.RETURN_SUCCESS, adminCli.execute("setproperties", workerPropertiesFile.getAbsolutePath()));
        } finally {
            assertEquals(CommandLineInterface.RETURN_SUCCESS, adminCli.execute("removeworker", "" + READ_ONLY_WORKER));
            FileUtils.deleteQuietly(workerPropertiesFile);
        }
    }

    /**
     * Test that removing a read-only worker using remote interface is not allowed.
     *
     * @throws Exception
     */
    @Test
    public void testRemoveWorkerShouldThrowException() throws Exception {
        final WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("NAME", "Test");

        Exception exception = null;
        try {
            mock.setupWorker(READ_ONLY_WORKER, null, workerConfig, new PlainSigner());
            mock.removeWorker(new AdminInfo("testRemoveWorkerShouldThrowException", null, null, null), READ_ONLY_WORKER);
        } catch (ReadOnlyWorkerException ex) {
            exception = ex;
        }
        assertNotNull("Expected ReadOnlyWorkerException but was null", exception);
        assertEquals("Worker " + READ_ONLY_WORKER + " is read-only", exception.getMessage());
    }

    /**
     * Test that removing a read-only worker using the REST interface is not allowed.
     *
     * @throws Exception
     */
    @Test
    public void testRemoveWorkerRestShouldReturn405() throws Exception {
        try {
            addDummyWorker();
            final Response resp =
                    callRest(Method.DELETE, 405, "", "/workers/" + READ_ONLY_WORKER, new JSONObject(), getAuthorizedStore());
            assertNotNull(resp);
            assertEquals(405, resp.getStatusCode());
            assertTrue(resp.getBody().asString().contains("Worker " + READ_ONLY_WORKER + " is read-only"));
        } finally {
            removeDummyWorker();
        }
    }

    /**
     * Test that removing a read-only worker using the AdminCLI is allowed.
     *
     * @throws UnexpectedCommandFailureException
     * @throws IOException
     */
    @Test
    public void testRemoveWorkerViaAdminCLIShouldSucceed() throws UnexpectedCommandFailureException, IOException {
        try {
            addDummyWorker();
            assertEquals(CommandLineInterface.RETURN_SUCCESS, adminCli.execute("removeworker", String.valueOf(READ_ONLY_WORKER)));
            // Confirm that worker has been removed
            assertEquals(CommandLineInterface.RETURN_INVALID_ARGUMENTS,
                    adminCli.execute("getstatus", "brief", String.valueOf(READ_ONLY_WORKER)));
        } catch (UnexpectedCommandFailureException ex) {
            // The exception we are looking for (InvalidWorkerIdException) is wrapped inside UnexpectedCommandFailureException
            final Throwable cause = ex.getCause();
            assertEquals(InvalidWorkerIdException.class, cause.getClass());
            assertEquals("No such worker: " + READ_ONLY_WORKER, cause.getMessage());
        }
    }

    /**
     * Test that setting a worker property on a read-only worker is not allowed using remote interface.
     */
    @Test
    public void testSetWorkerPropertyShouldThrowException() {
        final WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("NAME", "Test");

        Exception exception = null;
        try {
            mock.setupWorker(READ_ONLY_WORKER, null, workerConfig, new PlainSigner());
            mock.setWorkerProperty(new AdminInfo("testSetWorkerPropertyShouldThrowException", null, null ,null),
                    READ_ONLY_WORKER, "NAME", "Renamed");
        } catch (ReadOnlyWorkerException ex) {
            exception = ex;
        }
        assertNotNull("Expected ReadOnlyWorkerException but was null", exception);
        assertEquals("Worker " + READ_ONLY_WORKER + " is read-only", exception.getMessage());
    }

    /**
     * Test that setting a worker property on a read-only worker is allowed using AdminCLI interface.
     */
    @Test
    public void testSetWorkerPropertyViaAdminCLIShouldSucceed() throws UnexpectedCommandFailureException, IOException {
        try {
            addDummyWorker();
            final String newName = "Renamed";
            assertEquals(CommandLineInterface.RETURN_SUCCESS,
                    adminCli.execute("setproperty", String.valueOf(READ_ONLY_WORKER), "NAME", newName));
            assertEquals(CommandLineInterface.RETURN_SUCCESS,
                    adminCli.execute("getproperty", String.valueOf(READ_ONLY_WORKER), "NAME"));
            // Need to trim the string since the GetPropertyCommand appends some newline characters to the result
            final String out = adminCli.getOut().toString().trim();
            assertEquals(newName, out);
        } finally {
            removeDummyWorker();
        }
    }

    /**
     * Test that replacing worker properties on a read-only worker is not allowed using remote interface.
     *
     * @throws NoSuchWorkerException
     * @throws WorkerExistsException
     */
    @Test
    public void testReplaceWorkerPropertiesShouldThrowException() throws NoSuchWorkerException, WorkerExistsException {
        final WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("NAME", "Test");

        final HashMap<String, String> updatedProperties = new HashMap<>();
        updatedProperties.put("NAME", "Renamed");

        Exception exception = null;
        try {
            mock.setupWorker(READ_ONLY_WORKER, null, workerConfig, new PlainSigner());
            mock.replaceWorkerProperties(new AdminInfo("testReplaceWorkerPropertiesShouldThrowException", null, null, null),
                    READ_ONLY_WORKER, updatedProperties);
        } catch (ReadOnlyWorkerException ex) {
            exception = ex;
        }
        assertNotNull("Expected ReadOnlyWorkerException but was null", exception);
        assertEquals("Worker " + READ_ONLY_WORKER + " is read-only", exception.getMessage());
    }

    /**
     * Test that replacing worker properties on a read-only worker is not allowed using REST interface.
     *
     * @throws Exception
     */
    @Test
    public void testReplaceWorkerPropertiesRESTShouldReturn405() throws Exception {
        try {
            addDummyWorker();
            final JSONObject inner = new JSONObject();
            inner.put("NAME", "Renamed");
            final JSONObject outer = new JSONObject();
            outer.put("properties", inner);

            final Response resp =
                    callRest(Method.PUT, 405, "", "/workers/" + READ_ONLY_WORKER, outer, getAuthorizedStore());
            assertNotNull(resp);
            assertEquals(405, resp.getStatusCode());
            assertTrue(resp.getBody().asString().contains("Worker " + READ_ONLY_WORKER + " is read-only"));
        } finally {
            removeDummyWorker();
        }
    }

    /**
     * Tests that uploading a signer certificate on a read-only worker is not allowed using remote interface.
     *
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws CertBuilderException
     */
    @Test
    public void testUploadSignerCertificateShouldThrowException() throws NoSuchAlgorithmException, CertificateException, CertBuilderException {
        final WorkerConfig plainSignerConfig = new WorkerConfig();
        plainSignerConfig.setProperty("NAME", "Test");

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        final KeyPair rsaKeyPair = kpg.generateKeyPair();
        long currentTime = System.currentTimeMillis();

        // Create very simple self-signed certificate
        final String dn = "CN=testUploadSignerCertificateShouldThrowException";
        final X509CertificateHolder selfSignedCertHolder = new CertBuilder()
                .setNotBefore(new Date(currentTime - 120000))
                .setSelfSignKeyPair(new KeyPair(rsaKeyPair.getPublic(), rsaKeyPair.getPrivate()))
                .setIssuer(dn)
                .setSubject(dn)
                .build();

        final byte[] cert = new JcaX509CertificateConverter().getCertificate(selfSignedCertHolder).getEncoded();

        Exception exception = null;
        try {
            mock.setupWorker(READ_ONLY_WORKER, KeystoreCryptoToken.class.getName(), plainSignerConfig, new PlainSigner());
            mock.uploadSignerCertificate(new AdminInfo("testUploadSignerCertificateShouldThrowException", null, null, null),
                    READ_ONLY_WORKER, cert, null);
        } catch (ReadOnlyWorkerException ex) {
            exception = ex;
        }
        assertNotNull("Expected ReadOnlyWorkerException but was null", exception);
        assertEquals("Worker " + READ_ONLY_WORKER + " is read-only", exception.getMessage());
    }

    /**
     * Tests that uploading a signer certificate on a read-only worker using AdminCLI is allowed.
     *
     * @throws UnexpectedCommandFailureException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertBuilderException
     */
    @Test
    public void testUploadSignerCertificateViaAdminCLIShouldSucceed() throws UnexpectedCommandFailureException, IOException, NoSuchAlgorithmException, CertBuilderException {
        final String certificateInPemFileName = "testUploadSignerCertificateViaAdminCLIShouldSucceed" + System.currentTimeMillis();
        final File certificateInPemFile = File.createTempFile(certificateInPemFileName, ".pem");
        try {
            addDummyWorker();

            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            final KeyPair rsaKeyPair = kpg.generateKeyPair();
            long currentTime = System.currentTimeMillis();

            // Create very simple self-signed certificate
            final String dn = "CN=testUploadSignerCertificateViaAdminCLIShouldSucceed";
            final X509CertificateHolder selfSignedCertificateHolder = new CertBuilder()
                    .setNotBefore(new Date(currentTime - 120000))
                    .setSelfSignKeyPair(new KeyPair(rsaKeyPair.getPublic(), rsaKeyPair.getPrivate()))
                    .setIssuer(dn)
                    .setSubject(dn)
                    .build();

            // Write PEM to temp file
            final FileWriter fileWriterOut = new FileWriter(certificateInPemFile.getAbsolutePath());
            try (JcaPEMWriter writer = new JcaPEMWriter(fileWriterOut)) {
                writer.writeObject(selfSignedCertificateHolder);
            }

            assertEquals(CommandLineInterface.RETURN_SUCCESS, adminCli.execute("uploadsignercertificate",
                    String.valueOf(READ_ONLY_WORKER), "GLOB", certificateInPemFile.getAbsolutePath()));
            assertTrue(adminCli.getOut().toString().contains("Uploading the following signer certificate"));
            assertTrue(adminCli.getOut().toString().contains(dn));
        } finally {
            removeDummyWorker();
            FileUtils.deleteQuietly(certificateInPemFile);
        }
    }

    /**
     * Tests that uploading a signer certificate chain on a read-only worker using remote interface is not allowed.
     *
     * @throws NoSuchAlgorithmException
     * @throws CertBuilderException
     * @throws CertificateException
     */
    @Test
    public void testUploadSignerCertificateChainShouldThrowException() throws NoSuchAlgorithmException, CertBuilderException, CertificateException {
        final WorkerConfig plainSignerConfig = new WorkerConfig();
        plainSignerConfig.setProperty("NAME", "Test");

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        final KeyPair rsaKeyPair = kpg.generateKeyPair();
        long currentTime = System.currentTimeMillis();

        // Create very simple self-signed certificate
        final String dn = "CN=testUploadSignerCertificateChainShouldThrowException";
        final X509CertificateHolder selfSignedCertHolder = new CertBuilder()
                .setNotBefore(new Date(currentTime - 120000))
                .setSelfSignKeyPair(new KeyPair(rsaKeyPair.getPublic(), rsaKeyPair.getPrivate()))
                .setIssuer(dn)
                .setSubject(dn)
                .build();

        // Certificate chain containing one self-signed certificate
        final List<byte[]> chain =
                Arrays.asList(
                        new JcaX509CertificateConverter().getCertificate(selfSignedCertHolder).getEncoded()
                );

        Exception exception = null;
        try {
            mock.setupWorker(READ_ONLY_WORKER, KeystoreCryptoToken.class.getName(), plainSignerConfig, new PlainSigner());
            mock.uploadSignerCertificateChain(new AdminInfo("testUploadSignerCertificateChainShouldThrowException", null, null, null),
                    READ_ONLY_WORKER, chain, null);
        } catch (ReadOnlyWorkerException ex) {
            exception = ex;
        }
        assertNotNull("Expected ReadOnlyWorkerException but was null", exception);
        assertEquals("Worker " + READ_ONLY_WORKER + " is read-only", exception.getMessage());
    }

    /**
     * Tests that uploading a signer certificate chain on a read-only worker using AdminCLI is allowed.
     *
     * @throws UnexpectedCommandFailureException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertBuilderException
     */
    @Test
    public void testUploadSignerCertificateChainViaAdminCLIShouldSucceed() throws UnexpectedCommandFailureException, IOException, NoSuchAlgorithmException, CertBuilderException {
        final String certificateInPemFileName = "testUploadSignerCertificateChainViaAdminCLIShouldSucceed" + System.currentTimeMillis();
        final File certificateInPemFile = File.createTempFile(certificateInPemFileName, ".pem");
        try {
            addDummyWorker();

            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            final KeyPair caKeyPair = kpg.generateKeyPair();
            long currentTime = System.currentTimeMillis();

            // Create very simple self-signed certificate
            final String caDN = "CN=testUploadSignerCertificateChainViaAdminCLIShouldSucceedCA";
            final X509CertificateHolder caCertificateHolder = new CertBuilder()
                    .setNotBefore(new Date(currentTime - 120000))
                    .setSelfSignKeyPair(new KeyPair(caKeyPair.getPublic(), caKeyPair.getPrivate()))
                    .setIssuer(caDN)
                    .setSubject(caDN)
                    .build();

            final KeyPair signerCertKeyPair = kpg.generateKeyPair();

            // Create very simple self-signed certificate
            final String signerCertDN = "CN=testUploadSignerCertificateChainViaAdminCLIShouldSucceedSignerCert";
            final X509CertificateHolder signerCertificateHolder = new CertBuilder()
                    .setNotBefore(new Date(currentTime - 120000))
                    .setIssuer(caDN)
                    .setSubject(signerCertDN)
                    .setIssuerPrivateKey(caKeyPair.getPrivate())
                    .setSubjectPublicKey(signerCertKeyPair.getPublic())
                    .setSignatureAlgorithm("SHA256withRSA")
                    .build();

            // Write PEM to temp file
            final FileWriter fileWriterOut = new FileWriter(certificateInPemFile.getAbsolutePath());
            try (JcaPEMWriter writer = new JcaPEMWriter(fileWriterOut)) {
                writer.writeObject(caCertificateHolder);
                writer.writeObject(signerCertificateHolder);

            }

            assertEquals(CommandLineInterface.RETURN_SUCCESS, adminCli.execute("uploadsignercertificatechain",
                    String.valueOf(READ_ONLY_WORKER), "GLOB", certificateInPemFile.getAbsolutePath()));
            assertTrue(adminCli.getOut().toString().contains("Uploading the following signer certificate"));
            assertTrue(adminCli.getOut().toString().contains(caDN));
            assertTrue(adminCli.getOut().toString().contains(signerCertDN));
        } finally {
            removeDummyWorker();
            FileUtils.deleteQuietly(certificateInPemFile);
        }
    }

    /**
     * Tests that updating a worker property on a read-only worker using remote interface is not allowed.
     */
    @Test
    public void testUpdateWorkerPropertiesShouldThrowException() {
        final WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("NAME", "Test");

        final HashMap<String, String> propertiesAndValues = new HashMap<>();
        propertiesAndValues.put("NAME", "Renamed");

        Exception exception = null;
        try {
            mock.setupWorker(READ_ONLY_WORKER, null, workerConfig, new PlainSigner());
            mock.updateWorkerProperties(new AdminInfo("testUpdateWorkerPropertiesShouldThrowException", null, null ,null),
                    READ_ONLY_WORKER, propertiesAndValues, null);
        } catch (ReadOnlyWorkerException ex) {
            exception = ex;
        }
        assertNotNull("Expected ReadOnlyWorkerException but was null", exception);
        assertEquals("Worker " + READ_ONLY_WORKER + " is read-only", exception.getMessage());
    }

    /**
     * Tests that removing a worker property on a read-only worker is not allowed using remote interface.
     */
    @Test
    public void testRemoveWorkerPropertyShouldThrowException() {
        final WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("NAME", "Test");

        Exception exception = null;
        try {
            mock.setupWorker(READ_ONLY_WORKER, null, workerConfig, new PlainSigner());
            mock.removeWorkerProperty(new AdminInfo("testRemoveWorkerPropertyShouldThrowException", null, null ,null),
                    READ_ONLY_WORKER, "NAME");
        } catch (ReadOnlyWorkerException ex) {
            exception = ex;
        }
        assertNotNull("Expected ReadOnlyWorkerException but was null", exception);
        assertEquals("Worker " + READ_ONLY_WORKER + " is read-only", exception.getMessage());
    }

    /**
     * Tests that removing a worker property on a read-only worker using AdminCLI is allowed.
     *
     * @throws UnexpectedCommandFailureException
     * @throws IOException
     */
    @Test
    public void testRemoveWorkerPropertyViaAdminCLIShouldSucceed() throws UnexpectedCommandFailureException, IOException {
        try {
            addDummyWorker();
            assertEquals(CommandLineInterface.RETURN_SUCCESS,
                    adminCli.execute("removeproperty", String.valueOf(READ_ONLY_WORKER), "NAME"));
            final String out = adminCli.getOut().toString();
            assertTrue(out.contains("Removing the property NAME from worker " + READ_ONLY_WORKER));
        } finally {
            removeDummyWorker();
        }
    }

    /**
     * Test adding a legacy client certificate rule to a read-only worker using remote interface is not allowed.
     */
    @Test
    public void testAddAuthorizedClientShouldThrowException() {
        final WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("NAME", "Test");

        final AuthorizedClient authorizedClient = new AuthorizedClient();
        authorizedClient.setIssuerDN("CN=testAddAuthorizedClientShouldThrowException, O=SignServer Testing, C=SE");
        authorizedClient.setCertSN(new BigInteger("111114711").toString(16));

        Exception exception = null;
        try {
            mock.setupWorker(READ_ONLY_WORKER, null, workerConfig, new PlainSigner());
            mock.addAuthorizedClient(new AdminInfo("testAddAuthorizedClientShouldThrowException", null, null ,null),
                    READ_ONLY_WORKER, authorizedClient);
        } catch (ReadOnlyWorkerException ex) {
            exception = ex;
        }
        assertNotNull("Expected ReadOnlyWorkerException but was null", exception);
        assertEquals("Worker " + READ_ONLY_WORKER + " is read-only", exception.getMessage());
    }

    /**
     * Test adding a legacy client certificate rule to a read-only worker using AdminCLI is allowed.
     */
    @Test
    public void testAddAuthorizedClientViaAdminCLIShouldSucceed() throws UnexpectedCommandFailureException, IOException {
        try {
            addDummyWorker();
            final String certificateSn = "EF34242D2324";
            final String issuerDn = "CN=testAddAuthorizedClientViaAdminCLIShouldSucceed";

            assertEquals(CommandLineInterface.RETURN_SUCCESS,
                    adminCli.execute("addauthorizedclient", String.valueOf(READ_ONLY_WORKER), certificateSn, issuerDn));

            assertEquals(CommandLineInterface.RETURN_SUCCESS,
                    adminCli.execute("listauthorizedclients", String.valueOf(READ_ONLY_WORKER)));
            final String out = adminCli.getOut().toString();
            // For some reason, the command prints out the SN in lowercase
            assertTrue(out.contains(certificateSn.toLowerCase(Locale.ENGLISH)));
            assertTrue(out.contains(issuerDn));
        } finally {
            removeDummyWorker();
        }
    }

    /**
     * Test removing a legacy client certificate rule to a read-only worker using remote interface is not allowed.
     */
    @Test
    public void testRemoveAuthorizedClientShouldThrowException() {
        final WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("NAME", "Test");

        final AuthorizedClient authorizedClient = new AuthorizedClient();
        authorizedClient.setIssuerDN("CN=testRemoveAuthorizedClientShouldThrowException, O=SignServer Testing, C=SE");
        authorizedClient.setCertSN(new BigInteger("111114711").toString(16));
        workerConfig.addAuthorizedClient(authorizedClient);

        Exception exception = null;
        try {
            mock.setupWorker(READ_ONLY_WORKER, null, workerConfig, new PlainSigner());
            mock.removeAuthorizedClient(new AdminInfo("testRemoveAuthorizedClientShouldThrowException", null, null ,null),
                    READ_ONLY_WORKER, authorizedClient);
        } catch (ReadOnlyWorkerException ex) {
            exception = ex;
        }
        assertNotNull("Expected ReadOnlyWorkerException but was null", exception);
        assertEquals("Worker " + READ_ONLY_WORKER + " is read-only", exception.getMessage());
    }

    /**
     * Test removing a legacy client certificate rule to a read-only worker using AdminCLI is allowed.
     *
     * @throws UnexpectedCommandFailureException
     * @throws IOException
     */
    @Test
    public void testRemoveAuthorizedClientViaAdminCLIShouldSucceed() throws UnexpectedCommandFailureException, IOException {
        try {
            addDummyWorker();
            final String certificateSn = "EF34242D2324";
            final String issuerDn = "CN=testRemoveAuthorizedClientViaAdminCLIShouldSucceed";

            assertEquals(CommandLineInterface.RETURN_SUCCESS,
                    adminCli.execute("addauthorizedclient", String.valueOf(READ_ONLY_WORKER), certificateSn, issuerDn));

            assertEquals(CommandLineInterface.RETURN_SUCCESS,
                    adminCli.execute("removeauthorizedclient", String.valueOf(READ_ONLY_WORKER), certificateSn, issuerDn));

            final String out = adminCli.getOut().toString();
            assertTrue(out.contains("Client Removed"));
        } finally {
            removeDummyWorker();
        }
    }

    /**
     * Test adding a client certificate rule to a read-only worker using remote interface is not allowed.
     */
    @Test
    public void testAddAuthorizedClientGen2ShouldThrowException() {
        final WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("NAME", "Test");

        final CertificateMatchingRule certificateMatchingRule = new CertificateMatchingRule();
        certificateMatchingRule.setMatchIssuerWithType(MatchIssuerWithType.ISSUER_DN_BCSTYLE);
        certificateMatchingRule.setMatchIssuerWithValue("CN=testAddAuthorizedClientGen2ShouldThrowException");
        certificateMatchingRule.setMatchSubjectWithType(MatchSubjectWithType.CERTIFICATE_SERIALNO);
        certificateMatchingRule.setMatchSubjectWithValue("1234");

        Exception exception = null;
        try {
            mock.setupWorker(READ_ONLY_WORKER, null, workerConfig, new PlainSigner());
            mock.addAuthorizedClientGen2(new AdminInfo("testAddAuthorizedClientGen2ShouldThrowException", null, null ,null),
                    READ_ONLY_WORKER, certificateMatchingRule);
        } catch (ReadOnlyWorkerException ex) {
            exception = ex;
        }
        assertNotNull("Expected ReadOnlyWorkerException but was null", exception);
        assertEquals("Worker " + READ_ONLY_WORKER + " is read-only", exception.getMessage());
    }

    /**
     * Test adding a client certificate rule to a read-only worker using AdminCLI is allowed.
     *
     * @throws UnexpectedCommandFailureException
     * @throws IOException
     */
    @Test
    public void testAddAuthorizedClientGen2ViaAdminCLIShouldSucceed() throws UnexpectedCommandFailureException, IOException {
        try {
            addDummyWorker();
            final String matchSubjectWithType = "SUBJECT_RDN_CN";
            final String matchSubjectWithValue = "testAddAuthorizedClientViaAdminCLIShouldSucceed";
            final String matchIssuerWithType = "ISSUER_DN_BCSTYLE";
            final String matchIssuerWithValue = "CN=testAddAuthorizedClientViaAdminCLIShouldSucceed";
            final String description = "One ring to rule them all";
            assertEquals(CommandLineInterface.RETURN_SUCCESS,
            adminCli.execute("authorizedclients",
                    "-worker", String.valueOf(READ_ONLY_WORKER),
                    "-add",
                    "-matchSubjectWithType", matchSubjectWithType,
                    "-matchSubjectWithValue", matchSubjectWithValue,
                    "-matchIssuerWithType", matchIssuerWithType,
                    "-matchIssuerWithValue", matchIssuerWithValue,
                    "-description", description));
            final String out = adminCli.getOut().toString();
            assertTrue(out.contains(matchSubjectWithType));
            assertTrue(out.contains(matchSubjectWithValue));
            assertTrue(out.contains(matchIssuerWithType));
            assertTrue(out.contains(matchIssuerWithValue));
            assertTrue(out.contains(description));
        } finally {
            removeDummyWorker();
        }
    }

    /**
     * Test removing a client certificate rule to a read-only worker using remote interface is not allowed.
     */
    @Test
    public void testRemoveAuthorizedClientGen2ShouldThrowException() {
        final WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("NAME", "Test");

        final CertificateMatchingRule certificateMatchingRule = new CertificateMatchingRule();
        certificateMatchingRule.setMatchIssuerWithType(MatchIssuerWithType.ISSUER_DN_BCSTYLE);
        certificateMatchingRule.setMatchIssuerWithValue("CN=testRemoveAuthorizedClientGen2ShouldThrowException");
        certificateMatchingRule.setMatchSubjectWithType(MatchSubjectWithType.CERTIFICATE_SERIALNO);
        certificateMatchingRule.setMatchSubjectWithValue("1234");
        workerConfig.addAuthorizedClientGen2(certificateMatchingRule);

        Exception exception = null;
        try {
            mock.setupWorker(READ_ONLY_WORKER, null, workerConfig, new PlainSigner());
            mock.removeAuthorizedClientGen2(new AdminInfo("testRemoveAuthorizedClientGen2ShouldThrowException", null, null ,null),
                    READ_ONLY_WORKER, certificateMatchingRule);
        } catch (ReadOnlyWorkerException ex) {
            exception = ex;
        }
        assertNotNull("Expected ReadOnlyWorkerException but was null", exception);
        assertEquals("Worker " + READ_ONLY_WORKER + " is read-only", exception.getMessage());
    }

    /**
     * Test remove a client certificate rule to a read-only worker using AdminCLI is allowed.
     *
     * @throws UnexpectedCommandFailureException
     * @throws IOException
     */
    @Test
    public void testRemoveAuthorizedClientGen2ViaAdminCLIShouldSucceed() throws UnexpectedCommandFailureException, IOException {
        try {
            addDummyWorker();
            final String matchSubjectWithType = "SUBJECT_RDN_CN";
            final String matchSubjectWithValue = "testRemoveAuthorizedClientGen2ViaAdminCLIShouldSucceed";
            final String matchIssuerWithType = "ISSUER_DN_BCSTYLE";
            final String matchIssuerWithValue = "CN=testRemoveAuthorizedClientGen2ViaAdminCLIShouldSucceed";
            final String description = "One ring to rule them all";
            assertEquals(CommandLineInterface.RETURN_SUCCESS,
                    adminCli.execute("authorizedclients",
                            "-worker", String.valueOf(READ_ONLY_WORKER),
                            "-add",
                            "-matchSubjectWithType", matchSubjectWithType,
                            "-matchSubjectWithValue", matchSubjectWithValue,
                            "-matchIssuerWithType", matchIssuerWithType,
                            "-matchIssuerWithValue", matchIssuerWithValue,
                            "-description", description));

            assertEquals(CommandLineInterface.RETURN_SUCCESS,
                    adminCli.execute("authorizedclients",
                            "-worker", String.valueOf(READ_ONLY_WORKER),
                            "-remove",
                            "-matchSubjectWithType", matchSubjectWithType,
                            "-matchSubjectWithValue", matchSubjectWithValue,
                            "-matchIssuerWithType", matchIssuerWithType,
                            "-matchIssuerWithValue", matchIssuerWithValue,
                            "-description", description));

            final String out = adminCli.getOut().toString();
            assertTrue(out.contains("Rule removed"));
        } finally {
            removeDummyWorker();
        }
    }

    /**
     * Tests that add/update/delete the worker properties on a read-only worker using remote interface is not allowed.
     *
     * @throws NoSuchWorkerException
     * @throws WorkerExistsException
     */
    @Test
    public void testAddUpdateDeleteWorkerPropertiesShouldThrowException() throws NoSuchWorkerException, WorkerExistsException {
        final WorkerConfig workerConfig = new WorkerConfig();
        workerConfig.setProperty("NAME", "Test");

        final HashMap<String, String> properties = new HashMap<>();
        properties.put("NAME", "PatchedName");

        Exception exception = null;
        try {
            mock.setupWorker(READ_ONLY_WORKER,null, workerConfig, new PlainSigner());
            mock.addUpdateDeleteWorkerProperties(new AdminInfo("testAddUpdateDeleteWorkerPropertiesShouldThrowException", null, null, null),
                    READ_ONLY_WORKER, properties, Arrays.asList("NAME"));
        } catch (ReadOnlyWorkerException ex) {
            exception = ex;
        }
        assertNotNull("Expected ReadOnlyWorkerException but was null", exception);
        assertEquals("Worker " + READ_ONLY_WORKER + " is read-only", exception.getMessage());
    }

    /**
     * Tests that add/update/delete the worker properties on a read-only worker using the REST interface is not allowed.
     *
     * @throws Exception
     */
    @Test
    public void testAddUpdateDeleteWorkerPropertiesRESTShouldReturn405() throws Exception {
        try {
            addDummyWorker();
            final JSONObject inner = new JSONObject();
            inner.put("NAME", "PatchedName");
            final JSONObject outer = new JSONObject();
            outer.put("properties", inner);

            final Response resp =
                    callRest(Method.PATCH, 405, "", "/workers/" + READ_ONLY_WORKER, outer, getAuthorizedStore());
            assertNotNull(resp);
            assertEquals(405, resp.getStatusCode());
            assertTrue(resp.getBody().asString().contains("Worker " + READ_ONLY_WORKER + " is read-only"));
        } finally {
            removeDummyWorker();
        }
    }

    /**
     * Helper method to create simple dummy worker that only hold one property.
     * @throws IOException
     * @throws UnexpectedCommandFailureException
     */
    private void addDummyWorker() throws IOException, UnexpectedCommandFailureException {
        Properties properties = new Properties();
        final File workerPropertiesFile = new File("/tmp/testAddWorkerViaAdminCLI-" + System.currentTimeMillis() + ".properties");
        properties.put("WORKER" + READ_ONLY_WORKER + ".NAME", "ReadOnlyWorkersTest-" + System.currentTimeMillis());
        properties.put("WORKER" + READ_ONLY_WORKER + ".TYPE", "PROCESSABLE");
        try (FileOutputStream fos = new FileOutputStream(workerPropertiesFile)) {
            properties.store(fos, null);
        }

        adminCli.execute("setproperties", workerPropertiesFile.getAbsolutePath());
        FileUtils.deleteQuietly(workerPropertiesFile);
    }

    /**
     * Helper method to remove simple dummy worker.
     * @throws UnexpectedCommandFailureException
     * @throws IOException
     */
    private void removeDummyWorker() throws UnexpectedCommandFailureException, IOException {
        adminCli.execute("removeworker", String.valueOf(READ_ONLY_WORKER));
    }

}
