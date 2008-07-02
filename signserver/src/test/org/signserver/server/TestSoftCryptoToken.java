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

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;

import javax.crypto.Cipher;
import javax.naming.Context;
import javax.naming.InitialContext;

import junit.framework.TestCase;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;
import org.signserver.common.Base64SignerCertReqData;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.ICertReqData;
import org.signserver.common.MRTDSignRequest;
import org.signserver.common.MRTDSignResponse;
import org.signserver.common.PKCS10CertReqInfo;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;


public class TestSoftCryptoToken extends TestCase {

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
		   
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER88.CLASSPATH", "org.signserver.server.signers.MRTDSigner");
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER88.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.SoftCryptoToken");
		
		  
		  sSSession.setWorkerProperty(88, "AUTHTYPE", "NOAUTH");
		  String signserverhome = System.getenv("SIGNSERVER_HOME");
		  assertNotNull(signserverhome);
		  sSSession.setWorkerProperty(88,"KEYALG","RSA");
		  sSSession.setWorkerProperty(88, "KEYSPEC", "2048");		  
		  
		  sSSession.reloadConfiguration(88);	
	}

	public void test01BasicTests() throws Exception{
		SignerStatus stat = (SignerStatus) sSSession.getStatus(88);
		assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_OFFLINE);

		PKCS10CertReqInfo crInfo = new PKCS10CertReqInfo("SHA1WithRSA","CN=TEST1",null);
		ICertReqData reqData = sSSession.getCertificateRequest(88, crInfo);
		assertNotNull(reqData);
		assertTrue(reqData instanceof Base64SignerCertReqData);
		PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(Base64.decode(((Base64SignerCertReqData) reqData).getBase64CertReq()));
		assertTrue(pkcs10.getPublicKey() != null);

		KeyPair dummyCAKeys = KeyTools.genKeys("2048","RSA");
		X509Certificate cert = CertTools.genSelfCert(pkcs10.getCertificationRequestInfo().getSubject().toString(), 10, null, dummyCAKeys.getPrivate(), pkcs10.getPublicKey(), "SHA1WithRSA", false);
		sSSession.uploadSignerCertificate(88, cert, GlobalConfiguration.SCOPE_GLOBAL);		
		sSSession.reloadConfiguration(88);

		stat = (SignerStatus) sSSession.getStatus(88);
		assertTrue(stat.getActiveSignerConfig().getProperty("KEYDATA")!= null);
		assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);

		int reqid = 12;
		ArrayList<byte[]> signrequests = new ArrayList<byte[]>();

		byte[] signreq1 = "Hello World".getBytes();
		byte[] signreq2 = "Hello World2".getBytes();
		signrequests.add(signreq1);
		signrequests.add(signreq2);

		MRTDSignResponse res =  (MRTDSignResponse) sSSession.process(88, new MRTDSignRequest(reqid,signrequests), new RequestContext()); 		  
		assertTrue(res!=null);
		assertTrue(reqid == res.getRequestID());	      
		Certificate signercert = res.getSignerCertificate();	      
		assertNotNull(signercert);

		Cipher c = Cipher.getInstance("RSA", "BC");
		c.init(Cipher.DECRYPT_MODE, signercert);

		byte[] signres1 = c.doFinal((byte[]) ((ArrayList<?>) res.getProcessedData()).get(0));

		if (!arrayEquals(signreq1, signres1))
		{
			assertTrue("First MRTD doesn't match with request",false);
		}

		byte[] signres2 = c.doFinal((byte[]) ((ArrayList<?>) res.getProcessedData()).get(1));

		if (!arrayEquals(signreq2, signres2))
		{
			assertTrue("Second MRTD doesn't match with request",false);
		}	 

		assertTrue(signercert.getPublicKey().equals(pkcs10.getPublicKey()));

		reqData = sSSession.getCertificateRequest(88, crInfo);
		assertNotNull(reqData);
		assertTrue(reqData instanceof Base64SignerCertReqData);
		PKCS10CertificationRequest pkcs10_2 = new PKCS10CertificationRequest(Base64.decode(((Base64SignerCertReqData) reqData).getBase64CertReq()));
		assertTrue(pkcs10_2.getPublicKey() != null);
		assertFalse(pkcs10_2.getPublicKey().equals(pkcs10.getPublicKey()));
		
		sSSession.deactivateSigner(88);
		stat = (SignerStatus) sSSession.getStatus(88);
		assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_OFFLINE);
		try{
		  res =  (MRTDSignResponse) sSSession.process(88, new MRTDSignRequest(reqid,signrequests), new RequestContext());
		  assertTrue(false);
		}catch(CryptoTokenOfflineException e){}
		
		sSSession.activateSigner(88,"anypwd");
		stat = (SignerStatus) sSSession.getStatus(88);
		assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);
		res =  (MRTDSignResponse) sSSession.process(88, new MRTDSignRequest(reqid,signrequests), new RequestContext());
		
		
		
	}





	public void test99TearDownDatabase() throws Exception{
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER88.CLASSPATH");
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER88.SIGNERTOKEN.CLASSPATH");
		
		  
		  sSSession.removeWorkerProperty(88, "AUTHTYPE");
		  String signserverhome = System.getenv("SIGNSERVER_HOME");
		  assertNotNull(signserverhome);
		  sSSession.removeWorkerProperty(88,"KEYALG");
		  sSSession.removeWorkerProperty(88, "KEYALG");
		  sSSession.removeWorkerProperty(88,"KEYDATA");
		  
		  sSSession.reloadConfiguration(88);
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
  
	private boolean arrayEquals(byte[] signreq2, byte[] signres2) {
		boolean retval = true;
		
		if(signreq2.length != signres2.length){
			return false;
		}
		
		for(int i=0;i<signreq2.length;i++){
			if(signreq2[i] != signres2[i]){
				return false;
			}
		}
		return retval;
	}

}
