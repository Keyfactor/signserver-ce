package org.signserver.server.genericws;

import java.net.URL;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.xml.namespace.QName;

import junit.framework.TestCase;

import org.signserver.cli.CommonAdminInterface;
import org.signserver.common.SignServerUtil;
import org.signserver.common.clusterclassloader.MARFileParser;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.genericws.gen.DummyWS;
import org.signserver.server.genericws.gen.DummyWSService;
import org.signserver.testutils.TestUtils;
import org.signserver.testutils.TestingSecurityManager;

public class TestDummyWS extends TestCase {

	private static IWorkerSession.IRemote sSSession = null;
	private static String signserverhome;
	
	private static final int WORKERID = 7632;
	private static int moduleVersion;
	
	protected void setUp() throws Exception {
		super.setUp();
		SignServerUtil.installBCProvider();
		Context context = getInitialContext();		
		sSSession = (IWorkerSession.IRemote) context.lookup(IWorkerSession.IRemote.JNDI_NAME);
		signserverhome = System.getenv("SIGNSERVER_HOME");
        assertNotNull(signserverhome);
		TestUtils.redirectToTempOut();
		TestUtils.redirectToTempErr();
		TestingSecurityManager.install();
        CommonAdminInterface.BUILDMODE = "SIGNSERVER";
	}
	
	public void test00SetupDatabase() throws Exception {
		MARFileParser marFileParser = new MARFileParser(signserverhome +"/dist-server/dummyws.mar");
		moduleVersion = marFileParser.getVersionFromMARFile();
		
		TestUtils.assertSuccessfulExecution(new String[] {"module", "add",
				signserverhome +"/dist-server/dummyws.mar", "junittest"});		
	    assertTrue(TestUtils.grepTempOut("Loading module DUMMYWS"));
	    assertTrue(TestUtils.grepTempOut("Module loaded successfully."));

	    sSSession.reloadConfiguration(WORKERID);
	}
	
	public void test01TestDummyWS() throws Exception {
		QName qname = new QName("gen.genericws.server.signserver.org", "DummyWSService");
		DummyWSService dummywsservice = new DummyWSService(new URL("http://localhost:8080/signserver/ws/dummyws/dummyws?wsdl"),qname);
		DummyWS dummyws = dummywsservice.getDummyWSPort();
		String result = dummyws.test("Test");
		assertTrue(result.equals("Test"));
				
		result = dummyws.test("CertSN");
		assertTrue(result, result.startsWith("CN=Machine"));
		
		result = dummyws.test("workerid");
		assertTrue(result, result.startsWith("7632"));	
	}

   public void test99RemoveDatabase() throws Exception {
		TestUtils.assertSuccessfulExecution(new String[] {"removeworker",
		""+WORKERID});
		
		TestUtils.assertSuccessfulExecution(new String[] {"module", "remove","DUMMYWS", "" + moduleVersion});		
		assertTrue(TestUtils.grepTempOut("Removal of module successful."));
	    sSSession.reloadConfiguration(WORKERID);
   }
   
	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() throws Exception {
		super.tearDown();
		TestingSecurityManager.remove();
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
