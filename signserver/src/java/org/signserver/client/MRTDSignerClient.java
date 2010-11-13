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

import javax.naming.NamingException;

import org.signserver.common.IllegalRequestException;
import org.signserver.common.MRTDSignRequest;
import org.signserver.common.MRTDSignResponse;
import org.signserver.common.RequestContext;
import org.signserver.common.SignServerException;
import org.signserver.common.CryptoTokenOfflineException;
import org.signserver.common.ServiceLocator;
import org.signserver.ejb.interfaces.IWorkerSession;
/**
 * Client class connecting to the sign server and requesting 
 * signatures conforming to the MRTD standard.
 * 
 * 
 * @author Philip Vendil
 *
 */


public class MRTDSignerClient {
	


	/**
	 * Main constructor, does nothing
	 *
	 */
	public MRTDSignerClient() {}
	
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
			IWorkerSession.IRemote signsession 
                                = ServiceLocator.getInstance().lookupRemote(
                                    IWorkerSession.IRemote.class);
		
		return (MRTDSignResponse) signsession.process(1,request, new RequestContext());
		}catch(CryptoTokenOfflineException e){
			throw new SignServerException("Signer is offline. Activate it before continuing", e);
		} catch (IllegalRequestException e) {
			throw new SignServerException("Illegal Signature Request", e);			
		} catch (NamingException e) {
			throw new SignServerException("NamingException", e);		
		}		
	}
	


}
