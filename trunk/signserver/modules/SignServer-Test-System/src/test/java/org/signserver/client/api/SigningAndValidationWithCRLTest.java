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
package org.signserver.client.api;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.util.List;
import javax.naming.NamingException;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerType;
import org.signserver.common.util.PathUtil;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.server.cryptotokens.P12CryptoToken;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.validationservice.common.Validation;
import org.w3c.dom.Document;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests for client API with a CRLValidator.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SigningAndValidationWithCRLTest extends ModulesTestCase {

    /** Logger for this class. */
    private static final Logger LOG = Logger.getLogger(SigningAndValidationWithCRLTest.class);

    private static final int SIGNER1_WORKERID = 5676;
    private static final int CERTVALIDATION_WORKERID = 105;
    private static final int XMLVALIDATOR_WORKERID = 5677;
    private static final int[] WORKERS = new int[] {5676, 5679, 5681, 5682, 5683, 5802, 5803};

    private static final String SIGNER1_WORKER = "TestXMLSigner";
    private static final String CERTVALIDATION_WORKER = "CRLValidationWorker2";
    private static final String XMLVALIDATOR_WORKER = "XMLValidatorWorker2";
    private static final String KEYSTORE8_PASSWORD = "foo123";
    private static final String KEYSTORE8_ALIAS = "signer00001";

    private static File keystoreFileEndentity8;
    private static File crlWithCertOk;
    private static File crlWithCertRevoked;
    private static File crlToUse;

    private final WorkerSession workerSession = getWorkerSession();

    protected final SSLSocketFactory socketFactory;

    public SigningAndValidationWithCRLTest() throws Exception {
        socketFactory = setupSSLKeystores();
    }

    @Before
    public void setUp() throws Exception {

        keystoreFileEndentity8 = new File(PathUtil.getAppHome(), "res/test/dss10/dss10_keystore.p12");
        if (!keystoreFileEndentity8.exists()) {
            throw new FileNotFoundException("Keystore file: " + keystoreFileEndentity8.getAbsolutePath());
        }

        crlWithCertOk = new File(PathUtil.getAppHome(), "res/test/dss10/DSSRootCA10-4.crl");
        crlWithCertRevoked = new File(PathUtil.getAppHome(), "res/test/dss10/DSSRootCA10-5-6b88a95bd1b9f59d-revoked.crl");
        crlToUse = new File(PathUtil.getAppHome(), "tmp/DSSRootCA10-use.crl");

        if (!crlWithCertOk.exists()) {
            throw new FileNotFoundException("Missing CRL: "
                    + crlWithCertOk.getAbsolutePath());
        }
        if (!crlWithCertRevoked.exists()) {
            throw new FileNotFoundException("Missing CRL: "
                    + crlWithCertRevoked.getAbsolutePath());
        }

        // Start with CRL with no revoked certificate
        crlToUse.delete();
        copyFile(crlWithCertOk, crlToUse);

        if (!crlToUse.exists()) {
            throw new FileNotFoundException("Missing CRL: "
                    + crlToUse.getAbsolutePath());
        }
    }

    /**
     * Other test cases can override this method to run with a different
     * client API implementation.
     *
     * @return The ISigningAndValidation implementation to use.
     */
    protected ISigningAndValidation getSigningAndValidationImpl() {
        try {
            return new SigningAndValidationEJB();
        } catch (NamingException ex) {
            fail(ex.getMessage());
            return null;
        }
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        // XMLSIGNER: endentity1
        setupSigner(SIGNER1_WORKERID, SIGNER1_WORKER, keystoreFileEndentity8, KEYSTORE8_PASSWORD, KEYSTORE8_ALIAS);

        // VALIDATION
        workerSession.setWorkerProperty(CERTVALIDATION_WORKERID, "VAL1.ISSUER1.CRLPATHS", crlToUse.toURI().toString());
        setupValidation();

        // XMLVALIDATOR: module
        setProperties(new File(getSignServerHome(), "res/test/test-xmlvalidator-configuration.properties"));

        // XMLVALIDATOR: worker
        workerSession.setWorkerProperty(XMLVALIDATOR_WORKERID, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(XMLVALIDATOR_WORKERID, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.xmlvalidator.XMLValidator");
        workerSession.setWorkerProperty(XMLVALIDATOR_WORKERID, "NAME", XMLVALIDATOR_WORKER);
        workerSession.setWorkerProperty(XMLVALIDATOR_WORKERID, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(XMLVALIDATOR_WORKERID, "VALIDATIONSERVICEWORKER", CERTVALIDATION_WORKER);
        workerSession.reloadConfiguration(XMLVALIDATOR_WORKERID);
    }

    private void setupSigner(int workerId, String workerName, File keystore,
                             String keystorePassword, final String defaultAlias) throws Exception {
        workerSession.setWorkerProperty(workerId, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(workerId, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.module.xmlsigner.XMLSigner");
        workerSession.setWorkerProperty(workerId, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.P12CryptoToken");
        workerSession.setWorkerProperty(workerId, "NAME", workerName);
        workerSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(workerId, P12CryptoToken.KEYSTOREPATH, keystore.getAbsolutePath());
        workerSession.setWorkerProperty(workerId, P12CryptoToken.KEYSTOREPASSWORD, keystorePassword);
        workerSession.setWorkerProperty(workerId, P12CryptoToken.DEFAULTKEY,
                                        defaultAlias);
        workerSession.reloadConfiguration(workerId);

        // We are using a P12CryptoToken so we also need to activate it
        workerSession.activateSigner(new WorkerIdentifier(SIGNER1_WORKERID), KEYSTORE8_PASSWORD);
    }

    private void setupValidation() throws IOException {
        final String caPEM = FileUtils.readFileToString(new File(PathUtil.getAppHome(), "res/test/dss10/DSSRootCA10.cacert.pem"));
        workerSession.setWorkerProperty(CERTVALIDATION_WORKERID, WorkerConfig.TYPE, WorkerType.PROCESSABLE.name());
        workerSession.setWorkerProperty(CERTVALIDATION_WORKERID, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.validationservice.server.ValidationServiceWorker");
        workerSession.setWorkerProperty(CERTVALIDATION_WORKERID, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(CERTVALIDATION_WORKERID, "NAME", CERTVALIDATION_WORKER);
        workerSession.setWorkerProperty(CERTVALIDATION_WORKERID, "VAL1.CLASSPATH", "org.signserver.validationservice.server.CRLValidator");
        workerSession.setWorkerProperty(CERTVALIDATION_WORKERID, "VAL1.ISSUER1.CERTCHAIN", caPEM);
        workerSession.setWorkerProperty(CERTVALIDATION_WORKERID, "VAL1.TESTPROP", "TEST");
        workerSession.reloadConfiguration(CERTVALIDATION_WORKERID);
    }

    @Test
    public void test01SignAndValidate() throws Exception {

        ISigningAndValidation signserver = getSigningAndValidationImpl();

        GenericSignResponse result = signserver.sign("" + SIGNER1_WORKERID, SigningAndValidationTestData.DUMMY_XML1.getBytes());
        byte[] data = result.getProcessedData();

        // Output for manual inspection
        File file = new File(getSignServerHome() + File.separator + "tmp" + File.separator + "signed_endentity8.xml");
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }

        // Check certificate
        Certificate signercert = result.getSignerCertificate();
        assertNotNull(signercert);

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        // Validate
        GenericValidationResponse res = signserver.validate(XMLVALIDATOR_WORKER, data);
        assertTrue("valid document: " + getStatus(res), res.isValid());
    }

    @Test
    public void test02SigOkCertOk() throws Exception {

        // OK signature, OK cert
        byte[] data = SigningAndValidationTestData.TESTXML10.getBytes();

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        ISigningAndValidation signserver = getSigningAndValidationImpl();

        GenericValidationResponse res = signserver.validate(XMLVALIDATOR_WORKER, data);

        assertTrue("valid document: " + getStatus(res), res.isValid());
    }

    @Test
    public void test03SigInconsistentCertOk() throws Exception {

        // Inconsistent signature, OK cert
        byte[] data = SigningAndValidationTestData.TESTXML10.getBytes();

        // Modify data
        data[57] = 'o';
        data[58] = 'd';

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        ISigningAndValidation signserver = getSigningAndValidationImpl();

        GenericValidationResponse res = signserver.validate("" + XMLVALIDATOR_WORKERID, data);

        assertFalse("invalid document", res.isValid());
    }

    @Test
    public void test04SigOkCertUntrusted() throws Exception {

        // OK signature, untrusted cert
        byte[] data = SigningAndValidationTestData.TESTXML2.getBytes();

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        ISigningAndValidation signserver = getSigningAndValidationImpl();
        GenericValidationResponse res = signserver.validate("" + XMLVALIDATOR_WORKERID, data);

        assertFalse("invalid document", res.isValid());
    }

    @Test
    public void test05SigOkCertInconsistent() throws Exception {

        // OK signature, inconsistent cert
        byte[] data = SigningAndValidationTestData.TESTXML2.getBytes();

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        ISigningAndValidation signserver = getSigningAndValidationImpl();
        GenericValidationResponse res = signserver.validate("" + XMLVALIDATOR_WORKERID, data);

        assertFalse("invalid document", res.isValid());
        // TODO: check that it was invalid for the right reason!
    }

    @Test
    public void test06SigOkCertsMissing() throws Exception {

        // OK signature, wrong certificate
        {
            byte[] data = SigningAndValidationTestData.TESTXML33.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            ISigningAndValidation signserver = getSigningAndValidationImpl();
            GenericValidationResponse res = signserver.validate("" + XMLVALIDATOR_WORKERID, data);


            // Check certificate
            // Certificate signercert = res.getSignerCertificate();
            // assertNotNull(signercert);
            assertFalse("invalid document", res.isValid());
        }
        // TODO: check status (invalid for right reason)
    }

    @Test
    public void test07SigOkCertWrong() throws Exception {

        // OK signature, wrong certificate
        {
            byte[] data = SigningAndValidationTestData.TESTXML3.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            ISigningAndValidation signserver = getSigningAndValidationImpl();
            GenericValidationResponse res = signserver.validate("" + XMLVALIDATOR_WORKERID, data);

            // Check certificate
            // Certificate signercert = res.getSignerCertificate();
            // assertNotNull(signercert);
            assertFalse("invalid document", res.isValid());
        }
        // TODO: check status (invalid for right reason)
    }

    @Test
    public void test08SigOkCertInReverseOrder() throws Exception {

        // OK signature, first ca cert then signer cert
        byte[] data = SigningAndValidationTestData.TESTXML5.getBytes();

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        ISigningAndValidation signserver = getSigningAndValidationImpl();
        GenericValidationResponse res = signserver.validate("" + XMLVALIDATOR_WORKERID, data);

        assertTrue("valid document", res.isValid());

        // Check certificate and path
        Certificate signercert = res.getCertificateValidation().getCertificate();
        assertEquals("Signer certificate", "CN=signer00001,OU=Testing,O=SignServer,C=SE", CertTools.getSubjectDN(signercert));
        List<Certificate> caChain = res.getCertificateValidation().getCAChain();
        assertEquals("ca certificate 0", "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE", CertTools.getSubjectDN(caChain.get(0)));
        assertEquals("caChain length", 1, caChain.size());
        LOG.info("Status message: " + res.getCertificateValidation().getStatusMessage());
        assertEquals(Validation.Status.VALID, res.getCertificateValidation().getStatus());
    }

    /**
     * Changes the CRL to a CRL with the certificate revoked.
     */
    @Test
    public void test09SigOkCertRevokedByUpdatingFile() throws Exception {
        LOG.info("test09SigOkCertRevocedByUpdatingFile");

        // Change the file to be one with CRL revoked
        crlToUse.delete();
        copyFile(crlWithCertRevoked, crlToUse);


        // OK signature, revoked cert
        assertCertRevoked();
    }

    /**
     * Changes the URL to point to a CRL which is revoked.
     */
    @Test
    public void test10SigOkCertRevoked() throws Exception {
        LOG.info("test10SigOkCertRevoced");

        // Change to a CRL where endentity8 is revoked
        workerSession.setWorkerProperty(CERTVALIDATION_WORKERID,
                "VAL1.ISSUER1.CRLPATHS", crlWithCertRevoked.toURI().toString());
        setupValidation();

        // OK signature, revoked cert
        assertCertRevoked();
    }

    /** Ok signature, revoked cert. */
    private void assertCertRevoked() throws Exception {
        final byte[] data = SigningAndValidationTestData.TESTXML10.getBytes();

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        final ISigningAndValidation signserver = getSigningAndValidationImpl();
        final GenericValidationResponse res = signserver.validate(
                "" + XMLVALIDATOR_WORKERID, data);

        assertFalse("invalid document", res.isValid());

        // Check certificate
        assertNotNull(res.getCertificateValidation());

        // Note: The best would be if we could get REVOKED as status from the CRLValidator and could then test with:
        //assertEquals(Validation.Status.REVOKED, res.getCertificateValidation().getStatus());
        assertNotEquals(Validation.Status.VALID, res.getCertificateValidation().getStatus());
        LOG.info("Revoked cert status: "
                + res.getCertificateValidation().getStatusMessage());

        final Certificate cert = res.getSignerCertificate();
        assertNotNull(cert);
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        // XMLVALIDATOR
        removeWorker(XMLVALIDATOR_WORKERID);

        // VALIDATION SERVICE
        removeWorker(CERTVALIDATION_WORKERID);

        // XMLSIGNER
        for (int workerId : WORKERS) {
            removeWorker(workerId);
        }
    }

    private static String getStatus(GenericValidationResponse res) {
        if (res.isValid()) {
            return "valid";
        }
        if (res.getCertificateValidation() != null) {
            return res.getCertificateValidation().getStatusMessage();
        }
        return "null";
    }

    private void checkXmlWellFormed(InputStream in) {
        try {
            DocumentBuilderFactory dBF = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = dBF.newDocumentBuilder();
            // builder.setErrorHandler(new MyErrorHandler());

            Document doc = builder.parse(in);
            doc.toString();
        } catch (Exception e) {
            LOG.error("Not well formed XML", e);
            fail("Not well formed XML: " + e.getMessage());
        }
    }

    private void copyFile(final File in, final File out) throws Exception {
        try (FileInputStream fis = new FileInputStream(in); FileOutputStream fos = new FileOutputStream(out)) {
            final byte[] buf = new byte[1024];
            int i;
            while ((i = fis.read(buf)) != -1) {
                fos.write(buf, 0, i);
            }
        }
    }
}
