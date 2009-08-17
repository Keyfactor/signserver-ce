package org.signserver.protocol.validationservice.ws;

import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.xml.namespace.QName;

import junit.framework.TestCase;

import org.bouncycastle.jce.X509KeyUsage;
import org.ejbca.util.Base64;
import org.ejbca.util.keystore.KeyTools;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.protocol.validationservice.ws.gen.IllegalRequestException_Exception;
import org.signserver.protocol.validationservice.ws.gen.ValidationResponse;
import org.signserver.protocol.validationservice.ws.gen.ValidationWSService;
import org.signserver.validationservice.common.ValidationServiceConstants;
import org.signserver.validationservice.common.Validation.Status;
import org.signserver.validationservice.server.ValidationTestUtils;

public class TestValidationWS extends TestCase {

	private static IGlobalConfigurationSession.IRemote gCSession = null;
	private static IWorkerSession.IRemote sSSession = null;
	
	private static org.signserver.protocol.validationservice.ws.gen.ValidationWS validationWS;
	private static String validCert1;
	private static String revokedCert1;
	private static String identificationCert1;
	
	protected void setUp() throws Exception {
		super.setUp();
		
		SignServerUtil.installBCProvider();
		Context context = getInitialContext();
		gCSession = (IGlobalConfigurationSession.IRemote) context.lookup(IGlobalConfigurationSession.IRemote.JNDI_NAME);
		sSSession = (IWorkerSession.IRemote) context.lookup(IWorkerSession.IRemote.JNDI_NAME);
		
	}
	
	public void test00SetupDatabase() throws Exception{
		
		QName qname = new QName("gen.ws.validationservice.protocol.signserver.org", "ValidationWSService");
		ValidationWSService validationWSService = new ValidationWSService(new URL("http://localhost:8080/signserver/validationws/validationws?wsdl"),qname);
		validationWS =  validationWSService.getValidationWSPort();

		KeyPair validRootCA1Keys = KeyTools.genKeys("1024", "RSA");
		X509Certificate validRootCA1 = ValidationTestUtils.genCert("CN=ValidRootCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validRootCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

		KeyPair validSubCA1Keys = KeyTools.genKeys("1024", "RSA");
		X509Certificate validSubCA1 = ValidationTestUtils.genCert("CN=ValidSubCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validSubCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

		KeyPair validCert1Keys = KeyTools.genKeys("1024", "RSA");
		validCert1 = new String(Base64.encode(ValidationTestUtils.genCert("CN=ValidCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false).getEncoded()));
		revokedCert1 = new String(Base64.encode(ValidationTestUtils.genCert("CN=revokedCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false).getEncoded()));		
		identificationCert1 = new String(Base64.encode(ValidationTestUtils.genCert("CN=identificationCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false, X509KeyUsage.digitalSignature + X509KeyUsage.keyEncipherment).getEncoded()));
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
	}
	
	public void test01TestWSStatus() throws Exception{
		String status = validationWS.getStatus("ValTest");
		assertTrue(status != null);
		assertTrue(status, status.equals("ALLOK"));
		
		status = validationWS.getStatus("16");
		assertTrue(status != null);
		assertTrue(status, status.equals("ALLOK"));
		
		try{
			status = validationWS.getStatus("asdf");
			assertTrue(false);
		}catch(IllegalRequestException_Exception e){}
		
		try{
			status = validationWS.getStatus("17");
			assertTrue(false);
		}catch(IllegalRequestException_Exception e){}
	}

	public void test02TestWSisValid() throws Exception{
		ValidationResponse res = validationWS.isValid("ValTest", validCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		assertTrue(res != null);
		assertTrue(res.getStatusMessage() != null);
		assertTrue(res.getStatus().toString().equals(Status.VALID.toString()));
		assertTrue(res.getValidationDate() != null);
		assertTrue(res.getRevocationReason() == -1);
		assertTrue(res.getRevocationDate() == null);
		
		res = validationWS.isValid("16", validCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		assertTrue(res != null);
		assertTrue(res.getStatusMessage() != null);
		assertTrue(res.getStatus().toString().equals(Status.VALID.toString()));
		assertTrue(res.getValidationDate() != null);
		assertTrue(res.getRevocationReason() == -1);
		assertTrue(res.getRevocationDate() == null);
		
		try{
			validationWS.isValid("17", validCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
			assertTrue(false);
		}catch(IllegalRequestException_Exception e){}
		try{
			validationWS.isValid("asfd", validCert1, ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
			assertTrue(false);
		}catch(IllegalRequestException_Exception e){}
		
		try{
			validationWS.isValid("asfd", "1234", ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
			assertTrue(false);
		}catch(IllegalRequestException_Exception e){}
		
		res = validationWS.isValid("ValTest", revokedCert1,  ValidationServiceConstants.CERTPURPOSE_NO_PURPOSE);
		assertTrue(res != null);
		assertTrue(res.getStatusMessage() != null);
		assertTrue(res.getStatus().toString().equals(Status.REVOKED.toString()));
		assertTrue(res.getValidationDate() != null);
		assertTrue(res.getRevocationReason() == 3);
		assertTrue(res.getRevocationDate() != null);
		
		res = validationWS.isValid("ValTest", identificationCert1, ValidationServiceConstants.CERTPURPOSE_ELECTRONIC_SIGNATURE);
		assertTrue(res != null);
		assertTrue(res.getStatusMessage() != null);
		assertTrue(res.getStatus().toString().equals(Status.BADCERTPURPOSE.toString()));
		assertTrue(res.getValidationDate() != null);
		assertTrue(res.getRevocationReason() == -1);
		assertTrue(res.getRevocationDate() == null);
		
	}
	
	public void test99RemoveDatabase() throws Exception{
		  
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER16.CLASSPATH");
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER16.SIGNERTOKEN.CLASSPATH");

		  sSSession.removeWorkerProperty(16, "AUTHTYPE");
		  sSSession.removeWorkerProperty(16, "VAL1.CLASSPATH");
		  sSSession.removeWorkerProperty(16, "VAL1.TESTPROP");
		  sSSession.removeWorkerProperty(16, "VAL1.ISSUER1.CERTCHAIN");

		  
		  sSSession.reloadConfiguration(16);		   
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
