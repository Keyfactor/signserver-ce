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

package org.signserver.ejb;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.naming.Context;
import javax.naming.InitialContext;

import junit.framework.TestCase;

import org.signserver.common.AuthorizedClient;
import org.signserver.common.GlobalConfiguration;
import org.signserver.common.MRTDSignRequest;
import org.signserver.common.MRTDSignResponse;
import org.signserver.common.SignServerUtil;
import org.signserver.common.SignerConfig;
import org.signserver.common.SignerStatus;
import org.signserver.ejb.interfaces.IGlobalConfigurationSession;
import org.signserver.ejb.interfaces.IWorkerSession;

public class TestWorkerSessionBean extends TestCase {

    /** Home interface */
	private static IWorkerSession.IRemote sSSession = null;
	private static IGlobalConfigurationSession.IRemote gCSession = null;


    /**
     * Set up the test case
     */
    protected void setUp() throws Exception {
    	super.setUp();
		SignServerUtil.installBCProvider();
		Context context = getInitialContext();
		gCSession = (IGlobalConfigurationSession.IRemote) context.lookup(IGlobalConfigurationSession.IRemote.JNDI_NAME);
		sSSession = (IWorkerSession.IRemote) context.lookup(IWorkerSession.IRemote.JNDI_NAME);
    }

	public void test00SetupDatabase() throws Exception{
		   
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER3.CLASSPATH", "org.signserver.server.signers.MRTDSigner");
		  gCSession.setProperty(GlobalConfiguration.SCOPE_GLOBAL, "WORKER3.SIGNERTOKEN.CLASSPATH", "org.signserver.server.signtokens.HardCodedSignToken");
		
		  
		  sSSession.setWorkerProperty(3, "AUTHTYPE", "NOAUTH");
		  sSSession.setWorkerProperty(3, "NAME", "testWorker");
		  sSSession.reloadConfiguration(3);	
	}
    
	/*
	 * Test method for 'org.signserver.ejb.SignSessionBean.signData(int, ISignRequest)'
	 */
	public void test01SignData() throws Exception {  
       
       int reqid = 11;
       ArrayList<byte[]> signrequests = new ArrayList<byte[]>();
       
       byte[] signreq1 = "Hello World".getBytes();
       byte[] signreq2 = "Hello World2".getBytes();
       signrequests.add(signreq1);
       signrequests.add(signreq2);
       
       MRTDSignRequest req = new MRTDSignRequest(reqid, signrequests);
       MRTDSignResponse res = (MRTDSignResponse) sSSession.process(3, req, null, null);
       
       assertTrue(reqid == res.getRequestID());
       
       Certificate signercert = res.getSignerCertificate();       
       ArrayList<?> signatures = (ArrayList<?>) res.getProcessedData();
       assertTrue(signatures.size() == 2);       
       
       Cipher c = Cipher.getInstance("RSA", "BC");
       c.init(Cipher.DECRYPT_MODE, signercert);
       
       byte[] signres1 = c.doFinal((byte[]) ((ArrayList<?>) res.getProcessedData()).get(0));              
       
       if (!arrayEquals(signreq1, signres1))
       {
    	   assertTrue("First MRTD doesn't match with request, " + new String(signreq1) + " = " + new String(signres1),false);
       }
       
       byte[] signres2 = c.doFinal((byte[]) ((ArrayList<?>) res.getProcessedData()).get(1));
       
       if (!arrayEquals(signreq2, signres2))
       {
    	   assertTrue("Second MRTD doesn't match with request",false);
       }	        	   
       
	} 

	/*
	 * Test method for 'org.signserver.ejb.SignSessionBean.getStatus(int)'
	 */
	public void test02GetStatus() throws Exception{
	   
	   
	   assertTrue(((SignerStatus) sSSession.getStatus(3)).getTokenStatus() == SignerStatus.STATUS_ACTIVE ||
			   ((SignerStatus)sSSession.getStatus(3)).getTokenStatus() == SignerStatus.STATUS_OFFLINE);
	}

	/*
	 * 
	 * Test method for 'org.signserver.ejb.SignSessionBean.reloadConfiguration()'
	 */
	public void test03ReloadConfiguration() throws Exception{		   
		   sSSession.reloadConfiguration(0);
	}
	
	
	public void test04NameMapping() throws Exception{	
		   int id = sSSession.getWorkerId("testWorker");
		   assertTrue(""+ id , id == 3);
	}


	
	/*
	 * Test method for 'org.signserver.ejb.SignSessionBean.SetProperty(int, String, String)'
	 */
	public void test05SetProperty() throws Exception{		
		sSSession.setWorkerProperty(3,"test", "Hello World");
		
		Properties props = sSSession.getCurrentSignerConfig(3).getProperties();
		assertTrue(props.getProperty("TEST").equals("Hello World"));
	}
	/*
	 * Test method for 'org.signserver.ejb.SignSessionBean.RemoveProperty(int, String)'
	 */
	public void test06RemoveProperty() throws Exception{		
		sSSession.removeWorkerProperty(3,"test");
		
		Properties props = sSSession.getCurrentSignerConfig(3).getProperties();
		assertNull(props.getProperty("test"));
	}
	/*
	 * Test method for 'org.signserver.ejb.SignSessionBean.AddAuthorizedClient(int, AuthorizedClient)'
	 */
	public void test07AddAuthorizedClient() throws Exception{		
		AuthorizedClient authClient = new AuthorizedClient("123456","CN=testca");
		sSSession.addAuthorizedClient(3,authClient);
		
		Collection<?> result = new SignerConfig(sSSession.getCurrentSignerConfig(3)).getAuthorizedClients();
		boolean exists = false;
		Iterator<?> iter =result.iterator();
		while(iter.hasNext()){
		   AuthorizedClient next = (AuthorizedClient) iter.next();	
		   exists = exists || (next.getCertSN().equals("123456") && next.getIssuerDN().toString().equals("CN=testca"));
		}
	
		assertTrue(exists);
	}
	/*
	 * Test method for 'org.signserver.ejb.SignSessionBean.RemoveAuthorizedClient(int, AuthorizedClient)'
	 */
	public void test08RemoveAuthorizedClient() throws Exception{		
		int initialsize = new SignerConfig( sSSession.getCurrentSignerConfig(3)).getAuthorizedClients().size();
		AuthorizedClient authClient = new AuthorizedClient("123456","CN=testca");
		assertTrue(sSSession.removeAuthorizedClient(3,authClient));
		
		Collection<?> result = new SignerConfig( sSSession.getCurrentSignerConfig(3)).getAuthorizedClients();
		assertTrue(result.size() == initialsize-1);
		
		boolean exists = false;
		Iterator<?> iter =result.iterator();
		while(iter.hasNext()){
		   AuthorizedClient next = (AuthorizedClient) iter.next();	
		   exists = exists || (next.getCertSN().equals("123456") && next.getIssuerDN().toString().equals("CN=testca"));
		}
	
		assertFalse(exists);
	}
	
	public void test99TearDownDatabase() throws Exception{
		  sSSession.removeWorkerProperty(3, "AUTHTYPE");
		  sSSession.removeWorkerProperty(3, "NAME");
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
