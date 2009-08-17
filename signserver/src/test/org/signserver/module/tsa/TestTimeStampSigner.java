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

package org.signserver.module.tsa;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.InitialContext;

import junit.framework.TestCase;

import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
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


public class TestTimeStampSigner extends TestCase {

	
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
        assertNotNull(signserverhome);
        CommonAdminInterface.BUILDMODE = "SIGNSERVER";
	}
	
	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() throws Exception {
		super.tearDown();
		TestingSecurityManager.remove();
	}
	
	public void test00SetupDatabase() throws Exception{				
		   
		MARFileParser marFileParser = new MARFileParser(signserverhome +"/dist-server/tsa.mar");
		moduleVersion = marFileParser.getVersionFromMARFile();
		
		TestUtils.assertSuccessfulExecution(new String[] {"module", "add",
				signserverhome +"/dist-server/tsa.mar", "junittest"});		
	    assertTrue(TestUtils.grepTempOut("Loading module TSA"));
	    assertTrue(TestUtils.grepTempOut("Module loaded successfully."));

	    sSSession.reloadConfiguration(8901);
	}



	public void test01BasicTimeStamp() throws Exception{


		int reqid = 12;

		TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
		TimeStampRequest          timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
		byte[] requestBytes = timeStampRequest.getEncoded();
		
		GenericSignRequest signRequest = new GenericSignRequest(12, requestBytes);


		GenericSignResponse res = (GenericSignResponse) sSSession.process(8901,signRequest, new RequestContext()); 

		assertTrue(reqid == res.getRequestID());

		Certificate signercert = res.getSignerCertificate();

		assertNotNull(signercert);

		TimeStampResponse timeStampResponse =  new TimeStampResponse((byte[]) res.getProcessedData());
		timeStampResponse.validate(timeStampRequest);
	      
	}

	/*
	 * Test method for 'org.signserver.server.MRTDSigner.getStatus()'
	 */
	public void test02GetStatus() throws Exception {
		
		
		SignerStatus stat = (SignerStatus) sSSession.getStatus(8901);
		assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);		

	}

	public void test99TearDownDatabase() throws Exception{
		TestUtils.assertSuccessfulExecution(new String[] {"removeworker",
		"8901"});
		
		TestUtils.assertSuccessfulExecution(new String[] {"module", "remove","TSA", "" + moduleVersion});		
		assertTrue(TestUtils.grepTempOut("Removal of module successful."));
	    sSSession.reloadConfiguration(8901);
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
