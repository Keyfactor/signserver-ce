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

 
package org.signserver.client;

import java.rmi.RemoteException;
import java.util.Hashtable;

import javax.ejb.CreateException;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.rmi.PortableRemoteObject;

import org.signserver.common.IllegalSignRequestException;
import org.signserver.common.MRTDSignRequest;
import org.signserver.common.MRTDSignResponse;
import org.signserver.common.SignServerException;
import org.signserver.common.SignTokenOfflineException;
import org.signserver.ejb.SignServerSession;
import org.signserver.ejb.SignServerSessionHome;
/**
 * Client class connecting to the sign server and requesting 
 * signatures conforming to the MRTD standard.
 * 
 * 
 * @author Philip Vendil
 *
 */


public class MRTDSignerClient {
	
	private SignServerSessionHome signHome = null;

	/**
	 * Main constructor, does nothing
	 *
	 */
	public MRTDSignerClient() {}
	
	 /**
     * Get the home interface
	 * @throws NamingException 
     */
    protected org.signserver.ejb.SignServerSessionHome getHome() throws NamingException  {
    	if(signHome == null){
    		Context ctx = this.getInitialContext();
    		Object o = ctx.lookup("SignServerSession");
    		signHome = (org.signserver.ejb.SignServerSessionHome) PortableRemoteObject
    		.narrow(o, org.signserver.ejb.SignServerSessionHome.class);
    	}
    	return signHome;
    }
	
    protected Context getInitialContext() throws NamingException  {
    	Hashtable props = new Hashtable();
    	props.put(
    		Context.INITIAL_CONTEXT_FACTORY,
    		"org.jnp.interfaces.NamingContextFactory");
    	props.put(
    		Context.URL_PKG_PREFIXES,
    		"org.jboss.naming:org.jnp.interfaces");
    	props.put(Context.PROVIDER_URL, "jnp://localhost:14444");
    	Context ctx = new InitialContext(props);
    	return ctx;
    }
	
	/**
	 * Main method used to sign MRTD data.
	 *  
	 * @param request a MRTDSignRequest, cannot be null
	 * @return A MRTDSignResponse, never null
	 * @throws RemoteException if communication problems occur.
	 * @throws SignServerException is thrown for several reasons, see the message and the getCause class for more info.
	 */
	public MRTDSignResponse signData(MRTDSignRequest request) throws RemoteException, SignServerException {
		try{
		SignServerSession signsession = getHome().create();
		
		return (MRTDSignResponse) signsession.signData(1,request, null,null);
		}catch(SignTokenOfflineException e){
			throw new SignServerException("Signer is offline. Activate it before continuing", e);
		} catch (IllegalSignRequestException e) {
			throw new SignServerException("Illegal Signature Request", e);			
		} catch (CreateException e) {
			throw new SignServerException("Problem creating interface to the SignSession Bean", e);	
		} catch (NamingException e) {
			throw new SignServerException("NamingException", e);		
		}		
	}
	
/*    private void setSSLContext() throws Exception {
        final String keyFileName = "c:\\keystore.jks";
        final String storePass = "serverpwd";
        final String keyPass = storePass;
        final KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(keyFileName), storePass.toCharArray());
        final KeyStore trustStore = keyStore;
        final String keyAlias;
        {
            Enumeration aliases = keyStore.aliases();
            String tmp = "";
            while( aliases.hasMoreElements() ) {
                tmp = (String)aliases.nextElement();
                if ( keyStore.isKeyEntry(tmp) )
                    break;
            }
            keyAlias = tmp;
        }
                
    
        
        
      //  SSLContextForRMI.setKeyStore(keyStore, trustStore, keyAlias, keyPass);
    }
    */

}
