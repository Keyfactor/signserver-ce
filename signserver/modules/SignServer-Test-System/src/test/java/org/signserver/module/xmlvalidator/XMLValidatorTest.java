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
package org.signserver.module.xmlvalidator;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.log4j.Logger;
import org.cesecore.util.CertTools;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericValidationRequest;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.RemoteRequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.WorkerConfig;
import org.signserver.common.WorkerIdentifier;
import org.signserver.common.WorkerStatus;
import org.signserver.ejb.interfaces.ProcessSessionRemote;
import org.signserver.ejb.interfaces.WorkerSession;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.Validation.Status;
import org.w3c.dom.Document;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * TODO: Document me!
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class XMLValidatorTest extends ModulesTestCase {

    private static final Logger log = Logger.getLogger(XMLValidatorTest.class);

    /**
     * WORKERID used in this test case as defined in
     * junittest-part-config.properties
     */
    private static final WorkerIdentifier WORKERID = new WorkerIdentifier(5677);

    private static final String VALIDATION_WORKER = "TestValidationWorker";
    private static final String SIGNER2_ISSUERDN = "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE";
    private static final String SIGNER2_SUBJECTDN = "CN=signer00001,OU=Testing,O=SignServer,C=SE";
    private static final String SIGNEREC_ISSUERDN = "CN=ECCA";
    private static final String SIGNEREC_SUBJECTDN = "CN=TestXMLSignerEC,OU=Testing,O=SignServer,C=SE";

    private final WorkerSession workerSession = getWorkerSession();
    private final ProcessSessionRemote processSession = getProcessSession();

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        // VALIDATION SERVICE
        workerSession.setWorkerProperty(17, WorkerConfig.IMPLEMENTATION_CLASS, "org.signserver.validationservice.server.ValidationServiceWorker");
        workerSession.setWorkerProperty(17, WorkerConfig.CRYPTOTOKEN_IMPLEMENTATION_CLASS, "org.signserver.server.cryptotokens.KeystoreCryptoToken");
        workerSession.setWorkerProperty(17, "KEYSTOREPATH",
                getSignServerHome() + File.separator + "res" + File.separator +
                        "test" + File.separator + "dss10" + File.separator +
                        "dss10_signer1.p12");
        workerSession.setWorkerProperty(17, "KEYSTORETYPE", "PKCS12");
        workerSession.setWorkerProperty(17, "KEYSTOREPASSWORD", "foo123");
        workerSession.setWorkerProperty(17, "DEFAULTKEY", "Signer 1");
        workerSession.setWorkerProperty(17, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(17, "NAME", VALIDATION_WORKER);
        workerSession.setWorkerProperty(17, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
        workerSession.setWorkerProperty(17, "VAL1.ISSUER1.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + XMLValidatorTestData.CERT_ISSUER + "\n-----END CERTIFICATE-----\n");
        workerSession.setWorkerProperty(17, "VAL1.ISSUER2.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + XMLValidatorTestData.CERT_ISSUER4 + "\n-----END CERTIFICATE-----\n");
        workerSession.setWorkerProperty(17, "VAL1.ISSUER3.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + XMLValidatorTestData.CERT_ISSUER_ECDSA + "\n-----END CERTIFICATE-----\n");
        workerSession.setWorkerProperty(17, "VAL1.TESTPROP", "TEST");
        workerSession.setWorkerProperty(17, "VAL1.REVOKED", "");
        workerSession.reloadConfiguration(17);

        // XMLVALIDATOR
        setProperties(new File(getSignServerHome(), "res/test/test-xmlvalidator-configuration.properties"));
        workerSession.setWorkerProperty(WORKERID.getId(), "VALIDATIONSERVICEWORKER", VALIDATION_WORKER);
        workerSession.reloadConfiguration(WORKERID.getId());
    }

    @Test
    public void test01GetStatus() {
        try {
            WorkerStatus stat = workerSession.getStatus(WORKERID);
            assertNotNull(stat);
//			assertEquals(WorkerStatus.STATUS_ACTIVE, stat.getTokenStatus());
        } catch (InvalidWorkerIdException ex) {
            log.error("Worker not found", ex);
            fail(ex.getMessage());
        }
    }

    /**
     * Test validating with a correct signature and certificate.
     *
     * @param reqid Request ID to use
     * @param wi Worker ID
     * @param xml Document to validate
     * @param expectedSubjectDN Expected subject DN
     * @param expectedIssuerDN Expected issuer DN
     */
    private void testSigOkCertOk(final int reqid, final WorkerIdentifier wi, final String xml,
            final String expectedSubjectDN, final String expectedIssuerDN) {
        // OK signature, OK cert

        byte[] data = xml.getBytes();

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        try {
            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) processSession.process(wi, signRequest, new RemoteRequestContext());

            assertEquals("answer to right question", reqid, res.getRequestID());

            assertTrue("valid document", res.isValid());

            // Check certificate and path
            Certificate signercert = res.getCertificateValidation().getCertificate();
            assertEquals("Signer certificate", expectedSubjectDN, CertTools.getSubjectDN(signercert));
            List<Certificate> caChain = res.getCertificateValidation().getCAChain();
            assertEquals("ca certificate 0", expectedIssuerDN, CertTools.getSubjectDN(caChain.get(0)));
            assertEquals("caChain length", 1, caChain.size());
            log.info("Status message: " + res.getCertificateValidation().getStatusMessage());
            assertEquals(Validation.Status.VALID, res.getCertificateValidation().getStatus());

        } catch (IllegalRequestException e) {
            log.error("Illegal request", e);
            fail(e.getMessage());
        } catch (CryptoTokenOfflineException e) {
            log.error("Crypto token offline", e);
            fail(e.getMessage());
        } catch (SignServerException e) {
            log.error("SignServer error", e);
            fail(e.getMessage());
        }
    }

    @Test
    public void test02SigOkCertOk() {
        testSigOkCertOk(13, WORKERID, XMLValidatorTestData.TESTXML1, SIGNER2_SUBJECTDN, SIGNER2_ISSUERDN);
    }

    @Test
    public void test03SigInconsistentCertOk() throws Exception {
        // Inconsistent signature, OK cert
        int reqid = 14;
        {
            byte[] data = XMLValidatorTestData.TESTXML1.getBytes();

            // Modify data
            data[57] = 'o';
            data[58] = 'd';

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) processSession.process(WORKERID, signRequest, new RemoteRequestContext());

            assertEquals("answer to right question", reqid, res.getRequestID());

            assertFalse("invalid document", res.isValid());

            // Just check that it wasn't the certificate who made it invalid
            if (res.getCertificateValidation() != null) {
                assertEquals(Status.VALID, res.getCertificateValidation().getStatus());
            }
        }
    }

    @Test
    public void test04SigOkCertUntrusted() throws Exception {
        // OK signature, untrusted cert
        int reqid = 15;
        {
            byte[] data = XMLValidatorTestData.TESTXML2.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) processSession.process(WORKERID, signRequest, new RemoteRequestContext());

            assertEquals("answer to right question", reqid, res.getRequestID());

            assertFalse("invalid document", res.isValid());
            assertEquals("no ca chain", 0, res.getCAChain().size());
        }
    }

    @Test
    public void test05SigOkCertInconsistent() throws Exception {
        // OK signature, inconsistent cert
        int reqid = 16;
        {
            byte[] data = XMLValidatorTestData.TESTXML2.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) processSession.process(WORKERID, signRequest, new RemoteRequestContext());

            assertEquals("answer to right question", reqid, res.getRequestID());

            // Check certificate
            // Certificate signercert = res.getSignerCertificate();
            // assertNotNull(signercert);
            assertFalse("invalid document", res.isValid());
        }
        // TODO: check that it was invalid for the right reason!
    }

    @Test
    public void test06SigOkCertsMissing() throws Exception {
        // OK signature, wrong certificate
        int reqid = 17;
        {
            byte[] data = XMLValidatorTestData.TESTXML33.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) processSession.process(
                    WORKERID, signRequest, new RemoteRequestContext());

            assertEquals("answer to right question", reqid, res.getRequestID());

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
        int reqid = 18;
        {
            byte[] data = XMLValidatorTestData.TESTXML3.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) processSession.process(
                    WORKERID, signRequest, new RemoteRequestContext());

            assertEquals("answer to right question", reqid, res.getRequestID());

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
        int reqid = 19;
        {
            byte[] data = XMLValidatorTestData.TESTXML5.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) processSession.process(
                    WORKERID, signRequest, new RemoteRequestContext());

            assertEquals("answer to right question", reqid, res.getRequestID());

            assertTrue("valid document", res.isValid());

            // Check certificate and path
            Certificate signercert = res.getCertificateValidation().getCertificate();
            assertEquals("Signer certificate", SIGNER2_SUBJECTDN, CertTools.getSubjectDN(signercert));
            List<Certificate> caChain = res.getCertificateValidation().getCAChain();
            assertEquals("ca certificate 0", SIGNER2_ISSUERDN, CertTools.getSubjectDN(caChain.get(0)));
            assertEquals("caChain length", 1, caChain.size());
            log.info("Status message: " + res.getCertificateValidation().getStatusMessage());
            assertEquals(Validation.Status.VALID, res.getCertificateValidation().getStatus());
        }
    }

    @Test
    public void test090DocumentNotReturned() throws Exception {
        // Just some validation
        int reqid = 20;
        {
            byte[] data = XMLValidatorTestData.TESTXML5.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) processSession.process(
                    WORKERID, signRequest, new RemoteRequestContext());

            assertEquals("answer to right question", reqid, res.getRequestID());

            assertTrue("valid document", res.isValid());

            // Check certificate and path
            Certificate signercert = res.getCertificateValidation().getCertificate();
            assertEquals("Signer certificate", SIGNER2_SUBJECTDN, CertTools.getSubjectDN(signercert));
            List<Certificate> caChain = res.getCertificateValidation().getCAChain();
            assertEquals("ca certificate 0", SIGNER2_ISSUERDN, CertTools.getSubjectDN(caChain.get(0)));
            assertEquals("caChain length", 1, caChain.size());
            log.info("Status message: " + res.getCertificateValidation().getStatusMessage());
            assertEquals(Validation.Status.VALID, res.getCertificateValidation().getStatus());

            // The test
            byte[] processedData = res.getProcessedData();
            assertTrue(processedData == null || processedData.length == 0);
        }
    }

    @Test
    public void test11SigOkCertRevoced() throws Exception {
        workerSession.setWorkerProperty(17, "VAL1.REVOKED", SIGNER2_SUBJECTDN);
        workerSession.reloadConfiguration(17);

        // OK signature, revoced cert
        int reqid = 22;
        {
            byte[] data = XMLValidatorTestData.TESTXML1.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) processSession.process(WORKERID, signRequest, new RemoteRequestContext());

            assertEquals("answer to right question", reqid, res.getRequestID());

            assertFalse("invalid document", res.isValid());

            // Check certificate
            assertNotNull(res.getCertificateValidation());
            assertEquals(Validation.Status.REVOKED, res.getCertificateValidation().getStatus());
            log.info("Revoked cert status: " + res.getCertificateValidation().getStatusMessage());

            Certificate cert = res.getSignerCertificate();
            assertNotNull(cert);
        }

        // reset revocation
        workerSession.removeWorkerProperty(17, "VAL1.REVOKED");
        workerSession.reloadConfiguration(17);
    }

    // tests using SHA-2 RSA variants for the signature algorithm.

    @Test
    public void test12SigOkCertOkDSA() {
        testSigOkCertOk(23, WORKERID, XMLValidatorTestData.TESTXML1_DSA, "CN=xmlsigner4", "CN=DemoRootCA2,OU=EJBCA,O=SignServer Sample,C=SE");
    }

    @Test
    public void test13SigOkCertOkSHA256withRSA() {
        testSigOkCertOk(24, WORKERID, XMLValidatorTestData.TESTXML_SHA256withRSA, SIGNER2_SUBJECTDN, SIGNER2_ISSUERDN);
    }

    @Test
    public void test14SigOkCertOkSHA384withRSA() {
        testSigOkCertOk(25, WORKERID, XMLValidatorTestData.TESTXML_SHA384withRSA, SIGNER2_SUBJECTDN, SIGNER2_ISSUERDN);
    }

    @Test
    public void test15SigOkCertOkSHA512withRSA() {
        testSigOkCertOk(26, WORKERID, XMLValidatorTestData.TESTXML_SHA512withRSA, SIGNER2_SUBJECTDN, SIGNER2_ISSUERDN);
    }

    @Test
    public void test16SigOkCertOkSHA1withECDSA() {
        testSigOkCertOk(27, WORKERID, XMLValidatorTestData.TESTXML_SHA1withECDSA, SIGNEREC_SUBJECTDN, SIGNEREC_ISSUERDN);
    }

    @Test
    public void test17SigOkCertOkSHA256withECDSA() {
        testSigOkCertOk(28, WORKERID, XMLValidatorTestData.TESTXML_SHA256withECDSA, SIGNEREC_SUBJECTDN, SIGNEREC_ISSUERDN);
    }

    @Test
    public void test18SigOkCertOkSHA384withECDSA() {
        testSigOkCertOk(29, WORKERID, XMLValidatorTestData.TESTXML_SHA384withECDSA, SIGNEREC_SUBJECTDN, SIGNEREC_ISSUERDN);
    }

    @Test
    public void test19SigOkCertOkSHA512withECDSA() {
        testSigOkCertOk(30, WORKERID, XMLValidatorTestData.TESTXML_SHA512withECDSA, SIGNEREC_SUBJECTDN, SIGNEREC_ISSUERDN);
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKERID.getId());

        // Remove validation service worker
        removeWorker(17);
    }

    private void checkXmlWellFormed(InputStream in) {
        try {
            DocumentBuilderFactory dBF = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = dBF.newDocumentBuilder();
            // builder.setErrorHandler(new MyErrorHandler());

            Document doc = builder.parse(in);
            doc.toString();
        } catch (Exception e) {
            log.error("Not well formed XML", e);
            fail("Not well formed XML: " + e.getMessage());
        }
    }
}
