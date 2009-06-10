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

package org.signserver.validationservice.server;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.InitialContext;

import junit.framework.TestCase;

import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.ValidateRequest;
import org.signserver.validationservice.common.ValidateResponse;
import org.signserver.validationservice.common.Validation;
import org.signserver.validationservice.common.ValidationServiceConstants;

/**
 * Tests for the CRL Validator.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class TestCRLValidator extends TestCase {

	private static IGlobalConfigurationSession.IRemote gCSession;
	private static IWorkerSession.IRemote sSSession;
 
	private File signServerHome;

	/** RootCA1 */
	private static X509Certificate certRootCA1;
	
	/** EndEntity1 signed by RootCA1 */
	private static X509Certificate certEndEntity1;
	
	/** EndEntity2 signed by RootCA1 */
	private static X509Certificate certEndEntity2;

	/** CRL for RootCA1 */
	private static X509CRL crlRootCA1;

	
	protected void setUp() throws Exception {
		super.setUp();
		
		SignServerUtil.installBCProvider();
		
		Context context = getInitialContext();
		gCSession = (IGlobalConfigurationSession.IRemote) context.lookup(IGlobalConfigurationSession.IRemote.JNDI_NAME);
		sSSession = (IWorkerSession.IRemote) context.lookup(IWorkerSession.IRemote.JNDI_NAME);

		signServerHome = new File(System.getenv("SIGNSERVER_HOME"));
		assertTrue(signServerHome.exists());

		CommonAdminInterface.BUILDMODE = "SIGNSERVER";
	}

	public void test00SetupDatabase() throws Exception {

		File cdpFile = new File(signServerHome, "tmp" + File.separator + "rootca1.crl");
		URL cdpUrl = cdpFile.toURI().toURL();
		
		// Setup keys, certificates and CRLs
		KeyPair keysRootCA1 = KeyTools.genKeys("1024", "RSA");
		certRootCA1 = ValidationTestUtils.genCert("CN=RootCA1", "CN=RootCA1", keysRootCA1.getPrivate(), keysRootCA1.getPublic(), 
				new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

		KeyPair keysEndEntity1 = KeyTools.genKeys("1024", "RSA");
		certEndEntity1 = ValidationTestUtils.genCert("CN=EndEntity1", "CN=RootCA1", keysRootCA1.getPrivate(), keysEndEntity1.getPublic(), 
				new Date(0), new Date(System.currentTimeMillis() + 1000000), false, 0, cdpUrl);

		KeyPair keysEndEntity2 = KeyTools.genKeys("1024", "RSA");
		certEndEntity2 = ValidationTestUtils.genCert("CN=EndEntity2", "CN=RootCA1", keysRootCA1.getPrivate(), keysEndEntity2.getPublic(), 
				new Date(0), new Date(System.currentTimeMillis() + 1000000), false, 0, cdpUrl);

		ArrayList<RevokedCertInfo> revoked = new ArrayList<RevokedCertInfo>();
		revoked.add(new RevokedCertInfo("fingerprint", certEndEntity2.getSerialNumber(), new Date(),
				RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED, new Date(System.currentTimeMillis() + 1000000)));

		crlRootCA1 = ValidationTestUtils.genCRL(certRootCA1, keysRootCA1.getPrivate(), cdpUrl, revoked, 24, 1);
		
		// Write CRL to file
		OutputStream out = null;
		try {
			out = new FileOutputStream(cdpFile);
			out.write(crlRootCA1.getEncoded());
		} finally {
			if (out != null) {
				out.close();
			}
		}
		assertTrue(cdpFile.exists());
		assertTrue(cdpFile.canRead());

		ArrayList<X509Certificate> chain1 = new ArrayList<X509Certificate>();
		chain1.add(certRootCA1);

		// Setup worker
		gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER15.CLASSPATH", "org.signserver.validationservice.server.ValidationServiceWorker");
		gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER15.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");
		sSSession.setWorkerProperty(15, "AUTHTYPE", "NOAUTH");
		sSSession.setWorkerProperty(15, "VAL1.CLASSPATH", "org.signserver.validationservice.server.CRLValidator");
		sSSession.setWorkerProperty(15, "VAL1.ISSUER1.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(chain1));
		//sSSession.setWorkerProperty(15, "VAL1.ISSUER1.CRLPATHS", cdpUrl.toExternalForm());
		sSSession.reloadConfiguration(15);
	}

	/**
	 * Tests the certificate for EndEntity1 signed by RootCA1.
	 * The certificate is valid.
	 */
	public void test01NotRevoked() throws Exception {
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(certEndEntity1), ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());

		Validation val = res.getValidation();
		assertTrue(val != null);
		assertTrue(val.getStatus().equals(Validation.Status.VALID));
		assertTrue(val.getStatusMessage() != null);
		List<ICertificate> cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=RootCA1"));
		assertEquals("CN=EndEntity1", val.getCertificate().getSubject());
	}

	/**
	 * Tests the certificate for EndEntity2 signed by RootCA1.
	 * The certificate is revoked and included in the CRL.
	 */
	public void test02Revoked() throws Exception {
		ValidateRequest req = new ValidateRequest(ICertificateManager.genICertificate(certEndEntity2), ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		ValidateResponse res = (ValidateResponse) sSSession.process(15, req, new RequestContext());

		Validation val = res.getValidation();
		assertTrue(val != null);

		// Note: The best would be if we could get REVOKED as status from the CRLValidator and could then test with:
		//assertEquals(Validation.Status.REVOKED, val.getStatus());
		assertFalse(Validation.Status.VALID.equals(val.getStatus()));

		assertTrue(val.getStatusMessage() != null);
		List<ICertificate> cAChain = val.getCAChain();
		assertTrue(cAChain != null);
		assertTrue(cAChain.get(0).getSubject().equals("CN=RootCA1"));
		assertEquals("CN=EndEntity2", val.getCertificate().getSubject());
	}
	
	// TODO: Add more tests for the CRLValidator here

	public void test99RemoveDatabase() throws Exception {

		gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER15.CLASSPATH");
		gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER15.SIGNERTOKEN.CLASSPATH");

		sSSession.removeWorkerProperty(15, "AUTHTYPE");
		sSSession.removeWorkerProperty(15, "VAL1.CLASSPATH");
		sSSession.removeWorkerProperty(15, "VAL1.ISSUER1.CERTCHAIN");

		sSSession.reloadConfiguration(15);
	}

	/**
	 * Get the initial naming context
	 */
	protected Context getInitialContext() throws Exception {
		Hashtable<String, String> props = new Hashtable<String, String>();
		props.put(Context.INITIAL_CONTEXT_FACTORY, "org.jnp.interfaces.NamingContextFactory");
		props.put(Context.URL_PKG_PREFIXES, "org.jboss.naming:org.jnp.interfaces");
		props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
		Context ctx = new InitialContext(props);
		return ctx;
	}

}
