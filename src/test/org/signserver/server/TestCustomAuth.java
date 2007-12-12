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
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.InitialContext;

import junit.framework.TestCase;

import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.signserver.common.GenericSignRequest;
import org.signserver.common.GenericSignResponse;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;
import org.signserver.server.cryptotokens.HardCodedCryptoToken;
import org.signserver.server.cryptotokens.ICryptoToken;
import org.signserver.server.signers.TimeStampSigner;


public class TestCustomAuth extends TestCase {

	private static IGlobalConfigurationSession.IRemote gCSession = null;
	private static IWorkerSession.IRemote sSSession = null;
	
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
		  String signserverhome = System.getenv("SIGNSERVER_HOME");
		  assertNotNull(signserverhome);
		  sSSession.setWorkerProperty(9,"KEYSTOREPATH",signserverhome +"/src/test/timestamp1.p12");
		  sSSession.setWorkerProperty(9, "KEYSTOREPASSWORD", "foo123");
		  sSSession.setWorkerProperty(9,TimeStampSigner.DEFAULTTSAPOLICYOID,"1.0.1.2.33");
		  sSSession.setWorkerProperty(9,TimeStampSigner.TSA,"CN=TimeStampTest1");
		  
		  sSSession.reloadConfiguration(9);	
	}



	public void test01TestCustomAuth() throws Exception{
		genTimeStampRequest(1, null, null);

		try{
			genTimeStampRequest(2, null, null);
			assertTrue(false);
		}catch(IllegalRequestException e){}
		
		genTimeStampRequest(1, null, "1.2.3.4");
		try{
			genTimeStampRequest(1, null, "1.2.3.5");
			assertTrue(false);
		}catch(IllegalRequestException e){}
		
		HardCodedCryptoToken token = new HardCodedCryptoToken();
		token.init(new Properties());
		X509Certificate cert = (X509Certificate) token.getCertificate(ICryptoToken.PROVIDERUSAGE_SIGN);
		//System.out.println(CertTools.stringToBCDNString(cert.getSubjectDN().toString()));
		
		try{
			genTimeStampRequest(1, cert, null);
			assertTrue(false);
		}catch(IllegalRequestException e){}
		
	}
	
	private void genTimeStampRequest(int reqid, X509Certificate cert, String ip) throws Exception{
		

		
		TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
		TimeStampRequest          timeStampRequest = timeStampRequestGenerator.generate(TSPAlgorithms.SHA1, new byte[20], BigInteger.valueOf(100));
		byte[] requestBytes = timeStampRequest.getEncoded();

		GenericSignRequest req = new GenericSignRequest(reqid, requestBytes);


		GenericSignResponse res = (GenericSignResponse) sSSession.process(9,req, new RequestContext(cert,ip)); 

		assertTrue(reqid == res.getRequestID());

		Certificate signercert = res.getSignerCertificate();

		assertNotNull(signercert);

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
