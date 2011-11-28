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
import java.io.InputStream;
import java.security.cert.Certificate;
import java.util.List;

import javax.naming.NamingException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.log4j.Logger;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ServiceLocator;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.cryptotokens.P12CryptoToken;
import org.signserver.testutils.ModulesTestCase;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.Validation;
import org.w3c.dom.Document;

/**
 * Tests for client API with a CRLValidator.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class SigningAndValidationWithCRLTest extends ModulesTestCase {

    private static Logger log = Logger.getLogger(SigningAndValidationWithCRLTest.class);
    private static IWorkerSession.IRemote sSSession = null;
    private static IGlobalConfigurationSession.IRemote gCSession;
    
    private static final int SIGNER1_WORKERID = 5676;
    private static final int CERTVALIDATION_WORKERID = 105;
    private static final int XMLVALIDATOR_WORKERID = 5677;
    
    private static final String SIGNER1_WORKER = "TestXMLSigner";
    private static final String CERTVALIDATION_WORKER = "CRLValidationWorker2";
    private static final String XMLVALIDATOR_WORKER = "XMLValidatorWorker2";
    private static final String KEYSTORE8_PASSWORD = "foo123";
    
    private static String signserverhome;
    private static int moduleVersion;
    private static File keystoreFileEndentity8;
    private static File crlWithCertOk;
    private static File crlWithCertRevoked;
    private static File crlToUse;

    public SigningAndValidationWithCRLTest() {
        setupSSLKeystores();
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        gCSession = ServiceLocator.getInstance().lookupRemote(
                IGlobalConfigurationSession.IRemote.class);
        sSSession = ServiceLocator.getInstance().lookupRemote(
                IWorkerSession.IRemote.class);
        TestUtils.redirectToTempOut();
        TestUtils.redirectToTempErr();
        TestingSecurityManager.install();
        signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull("Please set SIGNSERVER_HOME environment variable", signserverhome);

        keystoreFileEndentity8 = new File(signserverhome + File.separator + "src/test/org/signserver/client/api/endentity8.p12");
        if (!keystoreFileEndentity8.exists()) {
            throw new FileNotFoundException("Keystore file: " + keystoreFileEndentity8.getAbsolutePath());
        }

        crlWithCertOk = new File(signserverhome + File.separator
                + "src/test/org/signserver/client/api/EightCA-ok.crl");
        crlWithCertRevoked = new File(signserverhome + File.separator
                + "src/test/org/signserver/client/api/EightCA-revoked.crl");
        crlToUse = new File(signserverhome + File.separator
                + "src/test/org/signserver/client/api/EightCA-use.crl");

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

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        TestingSecurityManager.remove();
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

    public void test00SetupDatabase() throws Exception {

        // XMLSIGNER: module
        MARFileParser marFileParser = new MARFileParser(signserverhome + "/dist-server/xmlsigner.mar");
        moduleVersion = marFileParser.getVersionFromMARFile();
        TestUtils.assertSuccessfulExecution(new String[]{"module", "add", signserverhome + "/dist-server/xmlsigner.mar", "junittest"});
        assertTrue(TestUtils.grepTempOut("Loading module XMLSIGNER"));
        assertTrue(TestUtils.grepTempOut("Module loaded successfully."));

        // XMLSIGNER: endentity1
        setupSigner(SIGNER1_WORKERID, SIGNER1_WORKER, keystoreFileEndentity8, KEYSTORE8_PASSWORD);


        // VALIDATION
        sSSession.setWorkerProperty(CERTVALIDATION_WORKERID, "VAL1.ISSUER1.CRLPATHS", crlToUse.toURI().toString());
        setupValidation();

        // XMLVALIDATOR: module
        marFileParser = new MARFileParser(signserverhome + "/dist-server/xmlvalidator.mar");
        moduleVersion = marFileParser.getVersionFromMARFile();
        TestUtils.assertSuccessfulExecution(new String[]{"module", "add", signserverhome + "/dist-server/xmlvalidator.mar", "junittest"});
        assertTrue(TestUtils.grepTempOut("Loading module XMLVALIDATOR"));
        assertTrue(TestUtils.grepTempOut("Module loaded successfully."));

        // XMLVALIDATOR: worker
        gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + CERTVALIDATION_WORKERID + ".CLASSPATH", "org.signserver.module.xmlvalidator.XMLValidator");
        gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + CERTVALIDATION_WORKERID + ".SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");
        sSSession.setWorkerProperty(XMLVALIDATOR_WORKERID, "NAME", XMLVALIDATOR_WORKER);
        sSSession.setWorkerProperty(XMLVALIDATOR_WORKERID, "AUTHTYPE", "NOAUTH");
        sSSession.setWorkerProperty(XMLVALIDATOR_WORKERID, "VALIDATIONSERVICEWORKER", CERTVALIDATION_WORKER);
        sSSession.reloadConfiguration(XMLVALIDATOR_WORKERID);
    }

    private void setupSigner(int workerId, String workerName, File keystore, String keystorePassword) throws Exception {
        gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".CLASSPATH", "org.signserver.module.xmlsigner.XMLSigner");
        gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + workerId + ".SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.P12CryptoToken");
        sSSession.setWorkerProperty(workerId, "NAME", workerName);
        sSSession.setWorkerProperty(workerId, "AUTHTYPE", "NOAUTH");
        sSSession.setWorkerProperty(workerId, P12CryptoToken.KEYSTOREPATH, keystore.getAbsolutePath());
        sSSession.setWorkerProperty(workerId, P12CryptoToken.KEYSTOREPASSWORD, keystorePassword);
        sSSession.reloadConfiguration(workerId);

        // We are using a P12CryptoToken so we also need to activate it
        sSSession.activateSigner(SIGNER1_WORKERID, KEYSTORE8_PASSWORD);
    }

    private void setupValidation() {
        gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + CERTVALIDATION_WORKERID + ".CLASSPATH", "org.signserver.validationservice.server.ValidationServiceWorker");
        gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + CERTVALIDATION_WORKERID + ".SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");
        sSSession.setWorkerProperty(CERTVALIDATION_WORKERID, "AUTHTYPE", "NOAUTH");
        sSSession.setWorkerProperty(CERTVALIDATION_WORKERID, "NAME", CERTVALIDATION_WORKER);
        sSSession.setWorkerProperty(CERTVALIDATION_WORKERID, "VAL1.CLASSPATH", "org.signserver.validationservice.server.CRLValidator");
        sSSession.setWorkerProperty(CERTVALIDATION_WORKERID, "VAL1.ISSUER1.CERTCHAIN", "-----BEGIN CERTIFICATE-----\n" + SigningAndValidationTestData.CERT_EIGHTCA + "\n-----END CERTIFICATE-----\n");
        sSSession.setWorkerProperty(CERTVALIDATION_WORKERID, "VAL1.TESTPROP", "TEST");
        sSSession.reloadConfiguration(CERTVALIDATION_WORKERID);
    }

    public void test01SignAndValidate() throws Exception {

        ISigningAndValidation signserver = getSigningAndValidationImpl();

        GenericSignResponse result = signserver.sign("" + SIGNER1_WORKERID, SigningAndValidationTestData.DUMMY_XML1.getBytes());
        byte[] data = result.getProcessedData();

        // Output for manual inspection
        File file = new File(signserverhome + File.separator + "tmp" + File.separator + "signed_endentity8.xml");
        FileOutputStream fos = new FileOutputStream(file);
        fos.write((byte[]) data);
        fos.close();

        // Check certificate
        Certificate signercert = result.getSignerCertificate();
        assertNotNull(signercert);

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        // Validate
        GenericValidationResponse res = signserver.validate(XMLVALIDATOR_WORKER, data);
        assertTrue("valid document: " + getStatus(res), res.isValid());
    }

    public void test02SigOkCertOk() throws Exception {

        // OK signature, OK cert
        byte[] data = SigningAndValidationTestData.TESTXML10.getBytes();

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        ISigningAndValidation signserver = getSigningAndValidationImpl();

        GenericValidationResponse res = signserver.validate(XMLVALIDATOR_WORKER, data);

        assertTrue("valid document: " + getStatus(res), res.isValid());
    }

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

    public void test04SigOkCertUntrusted() throws Exception {

        // OK signature, untrusted cert
        byte[] data = SigningAndValidationTestData.TESTXML2.getBytes();

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        ISigningAndValidation signserver = getSigningAndValidationImpl();
        GenericValidationResponse res = signserver.validate("" + XMLVALIDATOR_WORKERID, data);

        assertFalse("invalid document", res.isValid());
    }

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

    public void test08SigOkCertInReverseOrder() throws Exception {

        // OK signature, first ca cert then signer cert
        byte[] data = SigningAndValidationTestData.TESTXML5.getBytes();

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        ISigningAndValidation signserver = getSigningAndValidationImpl();
        GenericValidationResponse res = signserver.validate("" + XMLVALIDATOR_WORKERID, data);

        assertTrue("valid document", res.isValid());

        // Check certificate and path
        ICertificate signercert = res.getCertificateValidation().getCertificate();
        assertEquals("Signer certificate", "CN=endentity8", signercert.getSubject());
        List<ICertificate> caChain = res.getCertificateValidation().getCAChain();
        assertEquals("ca certificate 0", "CN=EightCA,O=EJBCA Testing,C=SE", caChain.get(0).getSubject());
        assertEquals("caChain length", 1, caChain.size());
        log.info("Status message: " + res.getCertificateValidation().getStatusMessage());
        assertEquals(Validation.Status.VALID, res.getCertificateValidation().getStatus());
    }

    /**
     * Changes the CRL to a CRL with the certificate revoked.
     * @throws Exception
     */
    public void test09SigOkCertRevokedByUpdatingFile() throws Exception {
        log.info("test09SigOkCertRevocedByUpdatingFile");

        // Change the file to be one with CRL revoked
        crlToUse.delete();
        copyFile(crlWithCertRevoked, crlToUse);


        // OK signature, revoked cert
        assertCertRevoked();
    }

    /**
     * Changes the URL to point to a CRL which is revoked.
     * @throws Exception
     */
    public void test10SigOkCertRevoked() throws Exception {
        log.info("test10SigOkCertRevoced");

        // Change to a CRL where endentity8 is revoked
        sSSession.setWorkerProperty(CERTVALIDATION_WORKERID,
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
        assertFalse(Validation.Status.VALID.equals(
                res.getCertificateValidation().getStatus()));
        log.info("Revoked cert status: "
                + res.getCertificateValidation().getStatusMessage());

        final ICertificate cert = res.getSignerCertificate();
        assertNotNull(cert);
    }

    public void test99TearDownDatabase() throws Exception {
        // XMLVALIDATOR
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker", "" + XMLVALIDATOR_WORKERID});
        TestUtils.assertSuccessfulExecution(new String[]{"module", "remove", "XMLVALIDATOR", "" + moduleVersion});
        assertTrue(TestUtils.grepTempOut("Removal of module successful."));
        sSSession.reloadConfiguration(XMLVALIDATOR_WORKERID);

        // VALIDATION SERVICE
        gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + CERTVALIDATION_WORKERID + ".CLASSPATH");
        gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER" + CERTVALIDATION_WORKERID + ".SIGNERTOKEN.CLASSPATH");
        sSSession.removeWorkerProperty(CERTVALIDATION_WORKERID, "AUTHTYPE");
        sSSession.removeWorkerProperty(CERTVALIDATION_WORKERID, "VAL1.CLASSPATH");
        sSSession.removeWorkerProperty(CERTVALIDATION_WORKERID, "VAL1.TESTPROP");
        sSSession.removeWorkerProperty(CERTVALIDATION_WORKERID, "VAL1.ISSUER1.CERTCHAIN");
        sSSession.removeWorkerProperty(CERTVALIDATION_WORKERID, "VAL1.ISSUER1.CRLPATHS");
        sSSession.reloadConfiguration(CERTVALIDATION_WORKERID);

        // XMLSIGNER
        TestUtils.assertSuccessfulExecution(new String[]{"removeworker", "" + SIGNER1_WORKERID});

        TestUtils.assertSuccessfulExecution(new String[]{"module", "remove", "XMLSIGNER", "" + moduleVersion});
        assertTrue(TestUtils.grepTempOut("Removal of module successful."));
        sSSession.reloadConfiguration(SIGNER1_WORKERID);
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
            log.error("Not well formed XML", e);
            fail("Not well formed XML: " + e.getMessage());
        }
    }

    private void copyFile(final File in, final File out) throws Exception {
        final FileInputStream fis = new FileInputStream(in);
        final FileOutputStream fos = new FileOutputStream(out);
        try {
            final byte[] buf = new byte[1024];
            int i = 0;
            while ((i = fis.read(buf)) != -1) {
                fos.write(buf, 0, i);
            }
        } finally {
            if (fis != null) {
                fis.close();
            }
            if (fos != null) {
                fos.close();
            }
        }
    }
}
