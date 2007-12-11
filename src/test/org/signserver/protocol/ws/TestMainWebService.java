package org.signserver.protocol.ws;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.xml.namespace.QName;

import junit.framework.TestCase;

import org.ejbca.util.Base64;
import org.ejbca.util.KeyTools;
import org.signserver.common.CryptoTokenAuthenticationFailureException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.InvalidWorkerIdException;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.protocol.ws.gen.InvalidWorkerIdException_Exception;
import org.signserver.protocol.ws.gen.SignServerWSService;
import org.signserver.protocol.ws.gen.WorkerStatusWS;
import org.signserver.server.signers.TimeStampSigner;
import org.signserver.validationservice.server.ValidationTestUtils;

public class TestMainWebService extends TestCase {

	private static IGlobalConfigurationSession.IRemote gCSession = null;
	private static IWorkerSession.IRemote sSSession = null;
	
	private static String validCert1;
	private static String revokedCert1;
	
	protected void setUp() throws Exception {
		super.setUp();
		SignServerUtil.installBCProvider();
		Context context = getInitialContext();
		gCSession = (IGlobalConfigurationSession.IRemote) context.lookup(IGlobalConfigurationSession.IRemote.JNDI_NAME);
		sSSession = (IWorkerSession.IRemote) context.lookup(IWorkerSession.IRemote.JNDI_NAME);
	}
	
	public void test00SetupDatabase() throws Exception{
		   
		gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER9.CLASSPATH", "org.signserver.server.signers.TimeStampSigner");
		gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER9.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.P12CryptoToken");


		sSSession.setWorkerProperty(9, "AUTHTYPE", "org.signserver.server.DummyAuthorizer");
		sSSession.setWorkerProperty(9, "TESTAUTHPROP", "DATA");
		sSSession.setWorkerProperty(9, "NAME", "TestTimeStamp");
		String signserverhome = System.getenv("SIGNSERVER_HOME");
		assertNotNull(signserverhome);
		sSSession.setWorkerProperty(9,"KEYSTOREPATH",signserverhome +"/src/test/timestamp1.p12");
		sSSession.setWorkerProperty(9, "KEYSTOREPASSWORD", "foo123");
		sSSession.setWorkerProperty(9,TimeStampSigner.DEFAULTTSAPOLICYOID,"1.0.1.2.33");
		sSSession.setWorkerProperty(9,TimeStampSigner.TSA,"CN=TimeStampTest1");

		sSSession.reloadConfiguration(9);	

		KeyPair validRootCA1Keys = KeyTools.genKeys("1024", "RSA");
		X509Certificate validRootCA1 = ValidationTestUtils.genCert("CN=ValidRootCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validRootCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

		KeyPair validSubCA1Keys = KeyTools.genKeys("1024", "RSA");
		X509Certificate validSubCA1 = ValidationTestUtils.genCert("CN=ValidSubCA1", "CN=ValidRootCA1", validRootCA1Keys.getPrivate(), validSubCA1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), true);

		KeyPair validCert1Keys = KeyTools.genKeys("1024", "RSA");
		validCert1 = new String(Base64.encode(ValidationTestUtils.genCert("CN=ValidCert1", "CN=ValidSubCA1", validSubCA1Keys.getPrivate(), validCert1Keys.getPublic(), new Date(0), new Date(System.currentTimeMillis() + 1000000), false).getEncoded()));
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

		sSSession.reloadConfiguration(16);		
	}
	
	

	public void testBasicWSStatuses() throws MalformedURLException, InvalidWorkerIdException_Exception, CryptoTokenAuthenticationFailureException, CryptoTokenOfflineException, InvalidWorkerIdException{
		
		QName qname = new QName("gen.ws.protocol.signserver.org", "SignServerWSService");
		SignServerWSService signServerWSService = new SignServerWSService(new URL("http://localhost:8080/signserver/signserverws/signserverws?wsdl"),qname);
		org.signserver.protocol.ws.gen.SignServerWS signServerWS =  signServerWSService.getSignServerWSPort();
		
		List<WorkerStatusWS> statuses = signServerWS.getStatus("9");
		assertTrue(statuses.size() == 1);
		assertTrue(statuses.get(0).getWorkerName().equals("9"));
		assertTrue(statuses.get(0).getOverallStatus().equals(org.signserver.protocol.ws.WorkerStatusWS.OVERALLSTATUS_ERROR));
		assertTrue(statuses.get(0).getErrormessage() != null);
		sSSession.activateSigner(9, "foo123");
		statuses = signServerWS.getStatus("TestTimeStamp");
		assertTrue(statuses.size() == 1);
		assertTrue(statuses.get(0).getWorkerName().equals("TestTimeStamp"));
		assertTrue(statuses.get(0).getOverallStatus().equals(org.signserver.protocol.ws.WorkerStatusWS.OVERALLSTATUS_ALLOK));
		assertTrue(statuses.get(0).getErrormessage() == null);
		/*
		statuses = signServerWS.getStatus(ISignServerWS.ALLWORKERS);
		assertTrue(statuses.size() == 2);
		assertTrue(statuses.get(0).getWorkerName().equals("9") || statuses.get(0).getWorkerName().equals("16"));
		assertTrue(statuses.get(1).getWorkerName().equals("9") || statuses.get(1).getWorkerName().equals("16"));
		*/
		
	}
	
	public void test99TearDownDatabase() throws Exception{
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER9.CLASSPATH");
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER9.SIGNERTOKEN.CLASSPATH");
		
		  
		  sSSession.removeWorkerProperty(9, "AUTHTYPE");
		  sSSession.removeWorkerProperty(9, "TESTAUTHPROP");
		  String signserverhome = System.getenv("SIGNSERVER_HOME");
		  assertNotNull(signserverhome);
		  sSSession.removeWorkerProperty(9,"KEYSTOREPATH");
		  sSSession.removeWorkerProperty(9, "KEYSTOREPASSWORD");
		  sSSession.removeWorkerProperty(9,TimeStampSigner.DEFAULTTSAPOLICYOID);
		  sSSession.removeWorkerProperty(9,TimeStampSigner.TSA);
		  
		  sSSession.reloadConfiguration(9);
		  
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER16.CLASSPATH");
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER16.SIGNERTOKEN.CLASSPATH");

		  sSSession.removeWorkerProperty(16, "AUTHTYPE");
		  sSSession.removeWorkerProperty(16, "VAL1.CLASSPATH");
		  sSSession.removeWorkerProperty(16, "VAL1.TESTPROP");
		  sSSession.removeWorkerProperty(16, "VAL1.ISSUER1.CERTCHAIN");

		  
		  sSSession.reloadConfiguration(16);	
	}
	
    /**
     * Get the initial naming context
     */
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
