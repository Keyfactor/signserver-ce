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
import org.ejbca.util.CertTools;
import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;
import org.signserver.common.*;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.Validation.Status;
import org.w3c.dom.Document;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class XMLValidatorTest extends ModulesTestCase {

    private static Logger log = Logger.getLogger(XMLValidatorTest.class);
	
    /**
     * WORKERID used in this test case as defined in
     * junittest-part-config.properties
     */
    private static final int WORKERID = 5677;
	
    private static final String VALIDATION_WORKER = "TestValidationWorker";
    private static final String SIGNER2_ISSUERDN = "CN=DSS Root CA 10,OU=Testing,O=SignServer,C=SE";
    private static final String SIGNER2_SUBJECTDN = "CN=Signer 2,OU=Testing,O=SignServer,C=SE";
	

    @Before
    public void setUp() throws Exception {
        SignServerUtil.installBCProvider();
    }

    @Test
    public void test00SetupDatabase() throws Exception {
        // VALIDATION SERVICE
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.CLASSPATH", "org.signserver.validationservice.server.ValidationServiceWorker");
        globalSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");
        workerSession.setWorkerProperty(17, "AUTHTYPE", "NOAUTH");
        workerSession.setWorkerProperty(17, "NAME", VALIDATION_WORKER);
        workerSession.setWorkerProperty(17, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
        workerSession.setWorkerProperty(17, "VAL1.ISSUER1.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + XMLValidatorTestData.CERT_ISSUER + "\n-----END CERTIFICATE-----\n");
        workerSession.setWorkerProperty(17, "VAL1.ISSUER2.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + XMLValidatorTestData.CERT_ISSUER4 + "\n-----END CERTIFICATE-----\n");
        workerSession.setWorkerProperty(17, "VAL1.TESTPROP", "TEST");
        workerSession.setWorkerProperty(17, "VAL1.REVOKED", "");
        workerSession.reloadConfiguration(17);

        // XMLVALIDATOR
        setProperties(new File(getSignServerHome(), "modules/SignServer-Module-XMLValidator/src/conf/junittest-part-config.properties"));
        workerSession.setWorkerProperty(WORKERID, "VALIDATIONSERVICEWORKER", VALIDATION_WORKER);
        workerSession.reloadConfiguration(WORKERID);
    }

    @Test
    public void test01GetStatus() {
        try {
            ValidatorStatus stat = (ValidatorStatus) workerSession.getStatus(WORKERID);
            assertNotNull(stat);
//			assertEquals(SignerStatus.STATUS_ACTIVE, stat.getTokenStatus());
        } catch (InvalidWorkerIdException ex) {
            log.error("Worker not found", ex);
            fail(ex.getMessage());
        }
    }
    
    private void testSigOkCertOk(final int workerId, final String xml,
            final String expectedSubjectDN, final String expectedIssuerDN) throws Exception {
        // OK signature, OK cert
        int reqid = 13;

        byte[] data = xml.getBytes();

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        try {
            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) workerSession.process(workerId, signRequest, new RequestContext());

            assertTrue("answer to right question", reqid == res.getRequestID());

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
    public void test02SigOkCertOk() throws Exception {
        testSigOkCertOk(WORKERID, XMLValidatorTestData.TESTXML1, SIGNER2_SUBJECTDN, SIGNER2_ISSUERDN);
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
            GenericValidationResponse res = (GenericValidationResponse) workerSession.process(WORKERID, signRequest, new RequestContext());

            assertTrue("answer to right question", reqid == res.getRequestID());

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
            GenericValidationResponse res = (GenericValidationResponse) workerSession.process(WORKERID, signRequest, new RequestContext());

            assertTrue("answer to right question", reqid == res.getRequestID());

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
            GenericValidationResponse res = (GenericValidationResponse) workerSession.process(WORKERID, signRequest, new RequestContext());

            assertTrue("answer to right question", reqid == res.getRequestID());

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
            GenericValidationResponse res = (GenericValidationResponse) workerSession.process(
                    WORKERID, signRequest, new RequestContext());

            assertTrue("answer to right question", reqid == res.getRequestID());

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
        int reqid = 17;
        {
            byte[] data = XMLValidatorTestData.TESTXML3.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) workerSession.process(
                    WORKERID, signRequest, new RequestContext());

            assertTrue("answer to right question", reqid == res.getRequestID());

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
        int reqid = 18;
        {
            byte[] data = XMLValidatorTestData.TESTXML5.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) workerSession.process(
                    WORKERID, signRequest, new RequestContext());

            assertTrue("answer to right question", reqid == res.getRequestID());

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
        int reqid = 19;
        {
            byte[] data = XMLValidatorTestData.TESTXML5.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) workerSession.process(
                    WORKERID, signRequest, new RequestContext());

            assertTrue("answer to right question", reqid == res.getRequestID());

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
    public void test091DocumentReturnedWithoutSignature() throws Exception {
        workerSession.setWorkerProperty(WORKERID, "RETURNDOCUMENT", "true");
        workerSession.setWorkerProperty(WORKERID, "STRIPSIGNATURE", "true");
        workerSession.reloadConfiguration(WORKERID);

        // Just some validation
        int reqid = 19;
        {
            byte[] data = XMLValidatorTestData.TESTXML5.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) workerSession.process(
                    WORKERID, signRequest, new RequestContext());

            assertTrue("answer to right question", reqid == res.getRequestID());

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
            assertNotNull(processedData);
            String document = new String(processedData);
            assertTrue(document.indexOf("Signature") == -1);
            assertTrue(document.indexOf("<my-tag>") != -1);
        }
    }

    @Test
    public void test11SigOkCertRevoced() throws Exception {
        workerSession.setWorkerProperty(17, "VAL1.REVOKED", SIGNER2_SUBJECTDN);
        workerSession.reloadConfiguration(17);

        // OK signature, revoced cert
        int reqid = 17;
        {
            byte[] data = XMLValidatorTestData.TESTXML1.getBytes();

            // XML Document
            checkXmlWellFormed(new ByteArrayInputStream(data));

            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) workerSession.process(WORKERID, signRequest, new RequestContext());

            assertTrue("answer to right question", reqid == res.getRequestID());

            assertFalse("invalid document", res.isValid());

            // Check certificate
            assertNotNull(res.getCertificateValidation());
            assertEquals(Validation.Status.REVOKED, res.getCertificateValidation().getStatus());
            log.info("Revoked cert status: " + res.getCertificateValidation().getStatusMessage());

            Certificate cert = res.getSignerCertificate();
            assertNotNull(cert);
        }
    }

    @Test
    public void test12SigOkCertOkDSA() throws Exception {
        testSigOkCertOk(WORKERID, XMLValidatorTestData.TESTXML1_DSA, "CN=xmlsigner4", "CN=DemoRootCA2,OU=EJBCA,O=SignServer Sample,C=SE");
    }

    @Test
    public void test99TearDownDatabase() throws Exception {
        removeWorker(WORKERID);

        workerSession.removeWorkerProperty(WORKERID, "RETURNDOCUMENT");
        workerSession.removeWorkerProperty(WORKERID, "STRIPSIGNATURE");
        workerSession.reloadConfiguration(WORKERID);

        // Remove validation service worker
        globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.CLASSPATH");
        globalSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.SIGNERTOKEN.CLASSPATH");
        workerSession.removeWorkerProperty(17, "AUTHTYPE");
        workerSession.removeWorkerProperty(17, "VAL1.CLASSPATH");
        workerSession.removeWorkerProperty(17, "VAL1.ISSUER1.CERTCHAIN");
        workerSession.removeWorkerProperty(17, "VAL1.TESTPROP");
        workerSession.removeWorkerProperty(17, "VAL1.REVOKED");
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
