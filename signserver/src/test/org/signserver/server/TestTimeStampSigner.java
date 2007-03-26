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

package org.signserver.server;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.rmi.PortableRemoteObject;

import junit.framework.TestCase;

import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignerStatus;
import org.signserver.ejb.IGlobalConfigurationSession;
import org.signserver.ejb.SignServerSession;
import org.signserver.ejb.SignServerSessionHome;
import org.signserver.server.signers.TimeStampSigner;


public class TestTimeStampSigner extends TestCase {

	private static IGlobalConfigurationSession gCSession = null;
	private static SignServerSession sSSession = null;
	
	protected void setUp() throws Exception {
		super.setUp();
		SignServerUtil.installBCProvider();
		gCSession = getGlobalConfigHome().create();
		sSSession = getSignServerHome().create();

	}
	
	public void test00SetupDatabase() throws Exception{
		   
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER4.CLASSPATH", "org.signserver.server.signers.TimeStampSigner");
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER4.SIGNERTOKEN.CLASSPATH", "org.signserver.server.signtokens.P12SignToken");
		
		  
		  sSSession.setWorkerProperty(4, "AUTHTYPE", "NOAUTH");
		  String signserverhome = System.getenv("SIGNSERVER_HOME");
		  assertNotNull(signserverhome);
		  sSSession.setWorkerProperty(4,"KEYSTOREPATH",signserverhome +"/src/test/timestamp1.p12");
		  sSSession.setWorkerProperty(4, "KEYSTOREPASSWORD", "foo123");
		  sSSession.setWorkerProperty(4,TimeStampSigner.DEFAULTTSAPOLICYOID,"1.0.1.2.33");
		  sSSession.setWorkerProperty(4,TimeStampSigner.TSA,"CN=TimeStampTest1");
		  
		  sSSession.reloadConfiguration(4);	
	}



	public void test01BasicTimeStamp() throws Exception{


		int reqid = 12;

		TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
		TimeStampRequest          timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
		byte[] requestBytes = timeStampRequest.getEncoded();
		
		GenericSignRequest signRequest = new GenericSignRequest(12, requestBytes);


		GenericSignResponse res = (GenericSignResponse) sSSession.signData(4,signRequest, null,null); 

		assertTrue(reqid == res.getRequestID());

		Certificate signercert = res.getSignerCertificate();

		assertNotNull(signercert);

		TimeStampResponse timeStampResponse =  new TimeStampResponse((byte[]) res.getSignedData());
		timeStampResponse.validate(timeStampRequest);
	      
	}

	/*
	 * Test method for 'org.signserver.server.MRTDSigner.getStatus()'
	 */
	public void test02GetStatus() throws Exception {
		
		
		SignerStatus stat = (SignerStatus) sSSession.getStatus(4);
		assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);		

	}

	public void test99TearDownDatabase() throws Exception{
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER4.CLASSPATH");
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER4.SIGNERTOKEN.CLASSPATH");
		
		  
		  sSSession.removeWorkerProperty(4, "AUTHTYPE");
		  String signserverhome = System.getenv("SIGNSERVER_HOME");
		  assertNotNull(signserverhome);
		  sSSession.removeWorkerProperty(4,"KEYSTOREPATH");
		  sSSession.removeWorkerProperty(4, "KEYSTOREPASSWORD");
		  sSSession.removeWorkerProperty(4,TimeStampSigner.DEFAULTTSAPOLICYOID);
		  sSSession.removeWorkerProperty(4,TimeStampSigner.TSA);
		  
		  sSSession.reloadConfiguration(4);
	}
	 
  /**
   * Get the home interface
   */
  protected org.signserver.ejb.IGlobalConfigurationSessionHome getGlobalConfigHome() throws Exception {
  	Context ctx = this.getInitialContext();
  	Object o = ctx.lookup("GlobalConfigurationSession");
  	org.signserver.ejb.IGlobalConfigurationSessionHome intf = (org.signserver.ejb.IGlobalConfigurationSessionHome) PortableRemoteObject
  		.narrow(o, org.signserver.ejb.IGlobalConfigurationSessionHome.class);
  	return intf;
  }
  
  /**
   * Get the home interface
   */
  protected SignServerSessionHome getSignServerHome() throws Exception {
  	Context ctx = this.getInitialContext();
  	Object o = ctx.lookup("SignServerSession");
  	org.signserver.ejb.SignServerSessionHome intf = (org.signserver.ejb.SignServerSessionHome) PortableRemoteObject
  		.narrow(o, org.signserver.ejb.SignServerSessionHome.class);
  	return intf;
  }
  
  /**
   * Get the initial naming context
   */
  protected Context getInitialContext() throws Exception {
  	Hashtable props = new Hashtable();
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
