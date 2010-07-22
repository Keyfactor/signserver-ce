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
import java.io.InputStream;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GenericValidationRequest;
import org.signserver.common.GenericValidationResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.SignServerUtil;
import org.signserver.common.ValidatorStatus;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.Validation.Status;
import org.w3c.dom.Document;


public class TestXMLValidator extends TestCase {

	private static Logger log = Logger.getLogger(TestXMLValidator.class);
	
	/**
	 * WORKERID used in this test case as defined in
	 * junittest-part-config.properties
	 */
	private static final int WORKERID = 5677;
	
	private static final String VALIDATION_WORKER = "TestValidationWorker";
	
	private IWorkerSession.IRemote sSSession;
	private IGlobalConfigurationSession.IRemote gCSession;
	
	private String signserverhome;
	private static int moduleVersion;
	
	protected void setUp() throws Exception {
		super.setUp();
		SignServerUtil.installBCProvider();
		Context context = getInitialContext();
		gCSession = (IGlobalConfigurationSession.IRemote) context.lookup(IGlobalConfigurationSession.IRemote.JNDI_NAME);
		sSSession = (IWorkerSession.IRemote) context.lookup(IWorkerSession.IRemote.JNDI_NAME);
		TestUtils.redirectToTempOut();
		TestUtils.redirectToTempErr();
		TestingSecurityManager.install();
		signserverhome = System.getenv("SIGNSERVER_HOME");
		assertNotNull("Please set SIGNSERVER_HOME environment variable",
				signserverhome);
		CommonAdminInterface.BUILDMODE = "SIGNSERVER";
	}

	@Override
	protected void tearDown() throws Exception {
		super.tearDown();
		TestingSecurityManager.remove();
	}

	public void test00SetupDatabase() throws Exception {

		MARFileParser marFileParser = new MARFileParser(signserverhome + "/dist-server/xmlvalidator.mar");
		moduleVersion = marFileParser.getVersionFromMARFile();
		
		// VALIDATION SERVICE
		gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.CLASSPATH", "org.signserver.validationservice.server.ValidationServiceWorker");
		gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");
		sSSession.setWorkerProperty(17, "AUTHTYPE", "NOAUTH");
		sSSession.setWorkerProperty(17, "NAME", VALIDATION_WORKER);
		sSSession.setWorkerProperty(17, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
		sSSession.setWorkerProperty(17, "VAL1.ISSUER1.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + XMLValidatorTestData.CERT_ISSUER + "\n-----END CERTIFICATE-----\n");
                sSSession.setWorkerProperty(17, "VAL1.ISSUER2.CERTCHAIN", "\n-----BEGIN CERTIFICATE-----\n" + XMLValidatorTestData.CERT_ISSUER4 + "\n-----END CERTIFICATE-----\n");
		sSSession.setWorkerProperty(17, "VAL1.TESTPROP", "TEST");
		sSSession.setWorkerProperty(17, "VAL1.REVOKED", "");
		sSSession.reloadConfiguration(17);
		
		// XMLVALIDATOR
		TestUtils.assertSuccessfulExecution(new String[] { "module", "add", signserverhome + "/dist-server/xmlvalidator.mar", "junittest" });
		assertTrue(TestUtils.grepTempOut("Loading module XMLVALIDATOR"));
		assertTrue(TestUtils.grepTempOut("Module loaded successfully."));
		sSSession.setWorkerProperty(WORKERID, "VALIDATIONSERVICEWORKER", VALIDATION_WORKER);
		sSSession.reloadConfiguration(WORKERID);
	}
	
	public void test01GetStatus() {
		try {
			ValidatorStatus stat = (ValidatorStatus) sSSession.getStatus(WORKERID);
                        assertNotNull(stat);
//			assertEquals(SignerStatus.STATUS_ACTIVE, stat.getTokenStatus());
		} catch(InvalidWorkerIdException ex) {
			log.error("Worker not found", ex);
			fail(ex.getMessage());
		}
	}

	public void test02SigOkCertOk() {

		// OK signature, OK cert
		int reqid = 13;
		
		byte[] data = XMLValidatorTestData.TESTXML1.getBytes();
		
		// XML Document
		checkXmlWellFormed(new ByteArrayInputStream(data));
		
		try {
			GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
			GenericValidationResponse res = (GenericValidationResponse) sSSession.process(WORKERID, signRequest, new RequestContext());
	
			assertTrue("answer to right question", reqid == res.getRequestID());
			
			assertTrue("valid document", res.isValid());
			
			// Check certificate and path
			ICertificate signercert = res.getCertificateValidation().getCertificate();
			assertEquals("Signer certificate", "CN=xmlsigner2,O=SignServer Test,C=SE", signercert.getSubject());
			List<ICertificate> caChain = res.getCertificateValidation().getCAChain(); 
			assertEquals("ca certificate 0", "CN=AdminTrunk2CA1,O=EJBCA Trunk3,C=SE", caChain.get(0).getSubject());
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
			GenericValidationResponse res = (GenericValidationResponse) sSSession.process(WORKERID, signRequest, new RequestContext());
	
			assertTrue("answer to right question", reqid == res.getRequestID());
			
			assertFalse("invalid document", res.isValid());
			
			// Just check that it wasn't the certificate who made it invalid
			if(res.getCertificateValidation() != null) {
				assertEquals(Status.VALID, res.getCertificateValidation().getStatus());
			}
		}
	}
		
	public void test04SigOkCertUntrusted() throws Exception {
		
		// OK signature, untrusted cert
		int reqid = 15;
		{
			byte[] data = XMLValidatorTestData.TESTXML2.getBytes();
			
			// XML Document
			checkXmlWellFormed(new ByteArrayInputStream(data));
			
			GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
			GenericValidationResponse res = (GenericValidationResponse) sSSession.process(WORKERID, signRequest, new RequestContext());
	
			assertTrue("answer to right question", reqid == res.getRequestID());
			
			assertFalse("invalid document", res.isValid());
			assertEquals("no ca chain", 0, res.getCAChain().size());
		}
	}
	
	public void test05SigOkCertInconsistent() throws Exception {
		
		// OK signature, inconsistent cert
		int reqid = 16;
		{
			byte[] data = XMLValidatorTestData.TESTXML2.getBytes();
			
			// XML Document
			checkXmlWellFormed(new ByteArrayInputStream(data));
			
			GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
			GenericValidationResponse res = (GenericValidationResponse) sSSession.process(WORKERID, signRequest, new RequestContext());
	
			assertTrue("answer to right question", reqid == res.getRequestID());
			
			// Check certificate
			// Certificate signercert = res.getSignerCertificate();
			// assertNotNull(signercert);
			assertFalse("invalid document", res.isValid());
		}
		// TODO: check that it was invalid for the right reason!
	}
	
	public void test06SigOkCertsMissing() throws Exception {
		
		// OK signature, wrong certificate
		int reqid = 17;
		{
			byte[] data = XMLValidatorTestData.TESTXML33.getBytes();
			
			// XML Document
			checkXmlWellFormed(new ByteArrayInputStream(data));
			
			GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
			GenericValidationResponse res = (GenericValidationResponse) sSSession.process(
					WORKERID, signRequest, new RequestContext());
	
			assertTrue("answer to right question", reqid == res.getRequestID());
			
			// Check certificate
			// Certificate signercert = res.getSignerCertificate();
			// assertNotNull(signercert);
			assertFalse("invalid document", res.isValid());
		}
		// TODO: check status (invalid for right reason)
	}
	
	public void test07SigOkCertWrong() throws Exception {
		
		// OK signature, wrong certificate
		int reqid = 17;
		{
			byte[] data = XMLValidatorTestData.TESTXML3.getBytes();
			
			// XML Document
			checkXmlWellFormed(new ByteArrayInputStream(data));
			
			GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
			GenericValidationResponse res = (GenericValidationResponse) sSSession.process(
					WORKERID, signRequest, new RequestContext());
	
			assertTrue("answer to right question", reqid == res.getRequestID());
			
			// Check certificate
			// Certificate signercert = res.getSignerCertificate();
			// assertNotNull(signercert);
			assertFalse("invalid document", res.isValid());
		}
		// TODO: check status (invalid for right reason)
	}
	
	public void test08SigOkCertInReverseOrder() throws Exception {
		
		// OK signature, first ca cert then signer cert
		int reqid = 18;
		{
			byte[] data = XMLValidatorTestData.TESTXML5.getBytes();
			
			// XML Document
			checkXmlWellFormed(new ByteArrayInputStream(data));
			
			GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
			GenericValidationResponse res = (GenericValidationResponse) sSSession.process(
					WORKERID, signRequest, new RequestContext());
	
			assertTrue("answer to right question", reqid == res.getRequestID());
			
			assertTrue("valid document", res.isValid());
			
			// Check certificate and path
			ICertificate signercert = res.getCertificateValidation().getCertificate();
			assertEquals("Signer certificate", "CN=xmlsigner2,O=SignServer Test,C=SE", signercert.getSubject());
			List<ICertificate> caChain = res.getCertificateValidation().getCAChain(); 
			assertEquals("ca certificate 0", "CN=AdminTrunk2CA1,O=EJBCA Trunk3,C=SE", caChain.get(0).getSubject());
			assertEquals("caChain length", 1, caChain.size());
			log.info("Status message: " + res.getCertificateValidation().getStatusMessage());
			assertEquals(Validation.Status.VALID, res.getCertificateValidation().getStatus());
		}
	}
	
        public void test09DocumentNotReturned() throws Exception {

            // Just some validation
            int reqid = 19;
            {
                    byte[] data = XMLValidatorTestData.TESTXML5.getBytes();

                    // XML Document
                    checkXmlWellFormed(new ByteArrayInputStream(data));

                    GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
                    GenericValidationResponse res = (GenericValidationResponse) sSSession.process(
                                    WORKERID, signRequest, new RequestContext());

                    assertTrue("answer to right question", reqid == res.getRequestID());

                    assertTrue("valid document", res.isValid());

                    // Check certificate and path
                    ICertificate signercert = res.getCertificateValidation().getCertificate();
                    assertEquals("Signer certificate", "CN=xmlsigner2,O=SignServer Test,C=SE", signercert.getSubject());
                    List<ICertificate> caChain = res.getCertificateValidation().getCAChain();
                    assertEquals("ca certificate 0", "CN=AdminTrunk2CA1,O=EJBCA Trunk3,C=SE", caChain.get(0).getSubject());
                    assertEquals("caChain length", 1, caChain.size());
                    log.info("Status message: " + res.getCertificateValidation().getStatusMessage());
                    assertEquals(Validation.Status.VALID, res.getCertificateValidation().getStatus());

                    // The test
                    byte[] processedData = res.getProcessedData();
                    assertTrue(processedData == null || processedData.length == 0);
            }
        }

        public void test19DocumentReturnedWithoutSignature() throws Exception {

            sSSession.setWorkerProperty(WORKERID, "RETURNDOCUMENT", "true");
            sSSession.setWorkerProperty(WORKERID, "STRIPSIGNATURE", "true");
            sSSession.reloadConfiguration(WORKERID);

            // Just some validation
            int reqid = 19;
            {
                    byte[] data = XMLValidatorTestData.TESTXML5.getBytes();

                    // XML Document
                    checkXmlWellFormed(new ByteArrayInputStream(data));

                    GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
                    GenericValidationResponse res = (GenericValidationResponse) sSSession.process(
                                    WORKERID, signRequest, new RequestContext());

                    assertTrue("answer to right question", reqid == res.getRequestID());

                    assertTrue("valid document", res.isValid());

                    // Check certificate and path
                    ICertificate signercert = res.getCertificateValidation().getCertificate();
                    assertEquals("Signer certificate", "CN=xmlsigner2,O=SignServer Test,C=SE", signercert.getSubject());
                    List<ICertificate> caChain = res.getCertificateValidation().getCAChain();
                    assertEquals("ca certificate 0", "CN=AdminTrunk2CA1,O=EJBCA Trunk3,C=SE", caChain.get(0).getSubject());
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

	public void test11SigOkCertRevoced() throws Exception {
		
		sSSession.setWorkerProperty(17, "VAL1.REVOKED", "CN=xmlsigner2,O=SignServer Test,C=SE");
		sSSession.reloadConfiguration(17);
		
		// OK signature, revoced cert
		int reqid = 17;
		{
			byte[] data = XMLValidatorTestData.TESTXML1.getBytes();
			
			// XML Document
			checkXmlWellFormed(new ByteArrayInputStream(data));
			
			GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
			GenericValidationResponse res = (GenericValidationResponse) sSSession.process(WORKERID, signRequest, new RequestContext());
	
			assertTrue("answer to right question", reqid == res.getRequestID());
			
			assertFalse("invalid document", res.isValid());
			
			// Check certificate
			assertNotNull(res.getCertificateValidation());
			assertEquals(Validation.Status.REVOKED, res.getCertificateValidation().getStatus());
			log.info("Revoked cert status: " + res.getCertificateValidation().getStatusMessage());
			
			ICertificate cert = res.getSignerCertificate();
			assertNotNull(cert);
		}
	}

    public void test12SigOkCertOkDSA() {

        // OK signature, OK cert
        final int reqid = 18;

        final byte[] data = XMLValidatorTestData.TESTXML1_DSA.getBytes();

        // XML Document
        checkXmlWellFormed(new ByteArrayInputStream(data));

        try {
            GenericValidationRequest signRequest = new GenericValidationRequest(reqid, data);
            GenericValidationResponse res = (GenericValidationResponse) sSSession.process(WORKERID, signRequest, new RequestContext());

            assertTrue("answer to right question", reqid == res.getRequestID());

            assertTrue("valid document", res.isValid());

            // Check certificate and path
            ICertificate signercert = res.getCertificateValidation().getCertificate();
            assertEquals("Signer certificate", "CN=xmlsigner4", signercert.getSubject());
            List<ICertificate> caChain = res.getCertificateValidation().getCAChain();
            assertEquals("ca certificate 0", "CN=DemoRootCA2,OU=EJBCA,O=SignServer Sample,C=SE", caChain.get(0).getSubject());
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
	

	public void test99TearDownDatabase() throws Exception {
		
		TestUtils.assertSuccessfulExecution(new String[] { "removeworker", "" + WORKERID });
		
		TestUtils.assertSuccessfulExecution(new String[] { "module", "remove", "XMLVALIDATOR", "" + moduleVersion });
		assertTrue(TestUtils.grepTempOut("Removal of module successful."));
                sSSession.removeWorkerProperty(WORKERID, "RETURNDOCUMENT");
                sSSession.removeWorkerProperty(WORKERID, "STRIPSIGNATURE");
		sSSession.reloadConfiguration(WORKERID);
		
		// Remove validation service worker
		gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.CLASSPATH");
		gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER17.SIGNERTOKEN.CLASSPATH");
		sSSession.removeWorkerProperty(17, "AUTHTYPE");
		sSSession.removeWorkerProperty(17, "VAL1.CLASSPATH");
		sSSession.removeWorkerProperty(17, "VAL1.ISSUER1.CERTCHAIN");
		sSSession.removeWorkerProperty(17, "VAL1.TESTPROP");
		sSSession.removeWorkerProperty(17, "VAL1.REVOKED");
	}

	/**
	 * Get the initial naming context
	 */
	private Context getInitialContext() throws Exception {
		Hashtable<String, String> props = new Hashtable<String, String>();
		props.put(Context.INITIAL_CONTEXT_FACTORY,
				"org.jnp.interfaces.NamingContextFactory");
		props.put(Context.URL_PKG_PREFIXES,
				"org.jboss.naming:org.jnp.interfaces");
		props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
		Context ctx = new InitialContext(props);
		return ctx;
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
