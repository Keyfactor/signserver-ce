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

package org.signserver.module.xmlsigner;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignerStatus;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;
import org.w3c.dom.Document;

/**
 * Tests for XMLSigner.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class TestXMLSigner extends TestCase {

	private static Logger log = Logger.getLogger(TestXMLSigner.class);
	
	/** WORKERID used in this test case as defined in junittest-part-config.properties */
	private static final int WORKERID = 5676;
	
	private static IWorkerSession.IRemote sSSession = null;
	private static String signserverhome;
	private static int moduleVersion;
	
	
	protected void setUp() throws Exception {
		super.setUp();
		SignServerUtil.installBCProvider();
		Context context = getInitialContext();
		sSSession = (IWorkerSession.IRemote) context.lookup(IWorkerSession.IRemote.JNDI_NAME);
		TestUtils.redirectToTempOut();
		TestUtils.redirectToTempErr();
		TestingSecurityManager.install();
		signserverhome = System.getenv("SIGNSERVER_HOME");
		assertNotNull("Please set SIGNSERVER_HOME environment variable", signserverhome);
		CommonAdminInterface.BUILDMODE = "SIGNSERVER";
	}

	@Override
	protected void tearDown() throws Exception {
		super.tearDown();
		TestingSecurityManager.remove();
	}	
	
	public void test00SetupDatabase() throws Exception {

		MARFileParser marFileParser = new MARFileParser(signserverhome + "/dist-server/xmlsigner.mar");
		moduleVersion = marFileParser.getVersionFromMARFile();

		TestUtils.assertSuccessfulExecution(new String[] { "module", "add", signserverhome + "/dist-server/xmlsigner.mar", "junittest" });
		assertTrue(TestUtils.grepTempOut("Loading module XMLSIGNER"));
		assertTrue(TestUtils.grepTempOut("Module loaded successfully."));

		sSSession.reloadConfiguration(WORKERID);
	}

	public void test01BasicXmlSign() throws Exception {

		int reqid = 13;

		GenericSignRequest signRequest = new GenericSignRequest(13, TESTXML1.getBytes());

		GenericSignResponse res = (GenericSignResponse) sSSession.process(WORKERID, signRequest, new RequestContext());
		byte[] data = res.getProcessedData();
		
		// Answer to right question
		assertTrue(reqid == res.getRequestID());
		
		// Output for manual inspection
		File file = new File(signserverhome + File.separator + "tmp" + File.separator + "signedxml.xml");
		FileOutputStream fos = new FileOutputStream(file);
		fos.write((byte[]) data);
		fos.close();

		// Check certificate
		Certificate signercert = res.getSignerCertificate();
		assertNotNull(signercert);

		// XML Document
		checkXmlWellFormed(new ByteArrayInputStream(data));
	}

	public void test02GetStatus() throws Exception {
		SignerStatus stat = (SignerStatus) sSSession.getStatus(WORKERID);
		assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);
	}

	public void test99TearDownDatabase() throws Exception {
		TestUtils.assertSuccessfulExecution(new String[] { "removeworker", ""+WORKERID });

		TestUtils.assertSuccessfulExecution(new String[] { "module", "remove", "XMLSIGNER", "" + moduleVersion });
		assertTrue(TestUtils.grepTempOut("Removal of module successful."));
		sSSession.reloadConfiguration(WORKERID);
	}

	/**
	 * Get the initial naming context
	 */
	private Context getInitialContext() throws Exception {
		Hashtable<String, String> props = new Hashtable<String, String>();
		props.put(Context.INITIAL_CONTEXT_FACTORY, "org.jnp.interfaces.NamingContextFactory");
		props.put(Context.URL_PKG_PREFIXES, "org.jboss.naming:org.jnp.interfaces");
		props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
		Context ctx = new InitialContext(props);
		return ctx;
	}

	private void checkXmlWellFormed(InputStream in) {
		try {
			DocumentBuilderFactory dBF = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = dBF.newDocumentBuilder();

			Document doc = builder.parse(in);
			doc.toString();
		} catch (Exception e) {
			log.error("Not well formed XML", e);
			fail("Not well formed XML: " + e.getMessage());
		}
	}
	
	private static final String TESTXML1 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root><my-tag>My Data</my-tag></root>";
}
