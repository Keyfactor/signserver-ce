package org.signserver.client.validationservice;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.InitialContext;

import junit.framework.TestCase;

import org.bouncycastle.jce.X509KeyUsage;
import org.ejbca.util.Base64;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;
import org.signserver.validationservice.server.ValidationTestUtils;

public class TestValidationCLI extends TestCase {

	private static String signserverhome;

	private static IGlobalConfigurationSession.IRemote gCSession = null;
	private static IWorkerSession.IRemote sSSession = null;
	
	private static String validCert1;
	private static String revokedCert1;

	private static String validcert1derpath;
	private static String validcert1path;
	private static String revokedcertpath;
	
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
        assertNotNull(signserverhome);
	}
	
	public void test00SetupDatabase() throws Exception{

		KeyPair validRootCA1Keys = KeyTools.genKeys("1024", "RSA");
		X509Certificate validRootCA1 = ValidationTestUtils.genCert("CN=ValidRootCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validRootCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

		KeyPair validSubCA1Keys = KeyTools.genKeys("1024", "RSA");
		X509Certificate validSubCA1 = ValidationTestUtils.genCert("CN=ValidSubCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validSubCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

		KeyPair validCert1Keys = KeyTools.genKeys("1024", "RSA");
		validCert1 = new String(Base64.encode(ValidationTestUtils.genCert("CN=ValidCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false, X509KeyUsage.digitalSignature + X509KeyUsage.keyEncipherment).getEncoded()));
		revokedCert1 = new String(Base64.encode(ValidationTestUtils.genCert("CN=revokedCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false).getEncoded()));				
		ArrayList<X509Certificate> validChain1 = new ArrayList<X509Certificate>();
		// Add in the wrong order
		validChain1.add(validRootCA1);
		validChain1.add(validSubCA1);

		gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER16.CLASSPATH", "org.signserver.validationservice.server.ValidationServiceWorker");
		gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER16.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");


		sSSession.setWorkerProperty(16, "AUTHTYPE", "NOAUTH");
		sSSession.setWorkerProperty(16, "NAME", "ValTest");
		sSSession.setWorkerProperty(16, "VAL1.CLASSPATH", "org.signserver.validationservice.server.DummyValidator");
		sSSession.setWorkerProperty(16, "VAL1.TESTPROP", "TEST");
		sSSession.setWorkerProperty(16, "VAL1.ISSUER1.CERTCHAIN", ValidationTestUtils.genPEMStringFromChain(validChain1));
		String signserverhome = System.getenv("SIGNSERVER_HOME");
		assertNotNull(signserverhome);

		sSSession.reloadConfiguration(16);		
		
		validcert1derpath = signserverhome + "/tmp/validcert1.cer";
		validcert1path = signserverhome + "/tmp/validcert1.pem";
		revokedcertpath = signserverhome + "/tmp/revokedcert1.pem";
		
		FileOutputStream fos = new FileOutputStream(validcert1derpath);
		fos.write(Base64.decode(validCert1.getBytes()));
		fos.close();
		fos = new FileOutputStream(validcert1path);
		fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
		fos.write(validCert1.getBytes());
		fos.write("\n-----END CERTIFICATE-----\n".getBytes());
		fos.close();
		fos = new FileOutputStream(revokedcertpath);
		fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
		fos.write(revokedCert1.getBytes());
		fos.write("\n-----END CERTIFICATE-----\n".getBytes());
		fos.close();
		
		TestingSecurityManager.remove();
	}
	
	public void testHelp() throws Exception{
		int result = TestUtils.assertFailedExecution(new ValidationCLI(),new String[] {});
		assertTrue(result == ValidationCLI.RETURN_BADARGUMENT);
		assertTrue(TestUtils.grepTempOut("Usage: "));
		result = TestUtils.assertFailedExecution(new ValidationCLI(),new String[] {"-help"});
		assertTrue(TestUtils.grepTempOut("Usage: "));
		assertTrue(result == ValidationCLI.RETURN_BADARGUMENT);
		
		TestingSecurityManager.remove();
	}
	
	public void testValidationCLI() {
			TestUtils.assertSuccessfulExecution(new ValidationCLI(),new String[] {"-hosts", "localhost", "-service", "16", "-cert", validcert1path});
			int result = TestUtils.assertFailedExecution(new ValidationCLI(),new String[] {"-hosts", "localhost", "-cert", validcert1path});
			assertTrue(result == ValidationCLI.RETURN_BADARGUMENT);
			result = TestUtils.assertFailedExecution(new ValidationCLI(),new String[] {"-service", "16", "-cert", validcert1path});
			assertTrue(result == ValidationCLI.RETURN_BADARGUMENT);
			result = TestUtils.assertFailedExecution(new ValidationCLI(),new String[] {"-hosts", "localhost", "-service", "16","-der","-pem", "-cert", validcert1path});
			assertTrue(result == ValidationCLI.RETURN_BADARGUMENT);
			TestUtils.assertSuccessfulExecution(new ValidationCLI(),new String[] {"-hosts", "localhost", "-service", "16", "-pem", "-cert", validcert1path});
			TestUtils.assertSuccessfulExecution(new ValidationCLI(),new String[] {"-hosts", "localhost", "-service", "16", "-der", "-port","8080", "-cert", validcert1derpath});
			result = TestUtils.assertFailedExecution(new ValidationCLI(),new String[] {"-hosts", "localhost", "-service", "16", "-der", "-port","8080", "-cert", revokedcertpath});
			assertTrue(result == ValidationCLI.RETURN_REVOKED);
			TestUtils.assertSuccessfulExecution(new ValidationCLI(),new String[] {"-hosts", "localhost", "-service", "16", "-der", "-port","8080", "-certpurposes","IDENTIFICATION", "-cert", validcert1derpath});
			TestUtils.assertSuccessfulExecution(new ValidationCLI(),new String[] {"-hosts", "localhost", "-service", "16", "-der", "-port","8080", "-certpurposes","IDENTIFICATION,ELECTROINIC_SIGNATURE", "-cert", validcert1derpath});
			result = TestUtils.assertFailedExecution(new ValidationCLI(),new String[] {"-hosts", "localhost", "-service", "16", "-der", "-port","8080", "-certpurposes","ELECTROINIC_SIGNATURE","-cert", revokedcertpath});
			assertTrue(result == ValidationCLI.RETURN_BADCERTPURPOSE);			

			TestingSecurityManager.remove();
	}
	

	public void test99RemoveDatabase() throws Exception{
		  
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER16.CLASSPATH");
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER16.SIGNERTOKEN.CLASSPATH");

		  sSSession.removeWorkerProperty(16, "AUTHTYPE");
		  sSSession.removeWorkerProperty(16, "VAL1.CLASSPATH");
		  sSSession.removeWorkerProperty(16, "VAL1.TESTPROP");
		  sSSession.removeWorkerProperty(16, "VAL1.ISSUER1.CERTCHAIN");

		  
		  sSSession.reloadConfiguration(16);
		  
		  TestingSecurityManager.remove();
	}
	
	protected Context getInitialContext() throws Exception {
		Hashtable<String, String> props = new Hashtable<String, String>();
		props.put(
				Context.INITIAL_CONTEXT_FACTORY,
		"org.jnp.interfaces.NamingContextFactory");
		props.put(
				Context.URL_PKG_PREFIXES,
		"org.jboss.naming:org.jnp.interfaces");
		props.put(Context.PROVIDER_URL, "jnp://localhost:1099");
		Context ctx = new InitialContext(props);
		return ctx;
	}

	


}
