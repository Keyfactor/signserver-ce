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

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Hashtable;

import javax.crypto.Cipher;
import javax.naming.Context;
import javax.naming.InitialContext;

import junit.framework.TestCase;

import org.signserver.common.GlobalConfiguration;
import org.signserver.common.MRTDSignRequest;
import org.signserver.common.MRTDSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;


public class TestMRTDSigner extends TestCase {


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
		   
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER3.CLASSPATH", "org.signserver.server.signers.MRTDSigner");
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER3.SIGNERTOKEN.CLASSPATH", "org.signserver.server.cryptotokens.HardCodedCryptoToken");
		
		  
		  sSSession.setWorkerProperty(3, "AUTHTYPE", "NOAUTH");
		  sSSession.reloadConfiguration(3);	
	}
	


	/*
	 * Test method for 'org.signserver.server.MRTDSigner.signData(ISignRequest)'
	 */

	public void testSignData() throws Exception{
		

		  
	      int reqid = 12;
	      ArrayList<byte[]> signrequests = new ArrayList<byte[]>();
	      
	      byte[] signreq1 = "Hello World".getBytes();
	      byte[] signreq2 = "Hello World2".getBytes();
	      signrequests.add(signreq1);
	      signrequests.add(signreq2);
		 		  
		  MRTDSignResponse res =  (MRTDSignResponse) sSSession.process(3, new MRTDSignRequest(reqid,signrequests), new RequestContext()); 		  
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

	/*
	 * Test method for 'org.signserver.server.MRTDSigner.getStatus()'
	 */
	public void testGetStatus() throws Exception{
	  SignerStatus stat = (SignerStatus) sSSession.getStatus(3);
	  assertTrue(stat.getTokenStatus() == SignerStatus.STATUS_ACTIVE);		
      
	}
	
	public void test99TearDownDatabase() throws Exception{
		  sSSession.removeWorkerProperty(3, "AUTHTYPE");
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER3.CLASSPATH");
		  gCSession.removeProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER3.SIGNERTOKEN.CLASSPATH");
		  sSSession.reloadConfiguration(3);
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
