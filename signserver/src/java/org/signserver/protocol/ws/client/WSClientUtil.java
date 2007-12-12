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

package org.signserver.protocol.ws.client;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.signserver.protocol.ws.gen.ProcessRequestWS;
import org.signserver.protocol.ws.gen.ProcessResponseWS;




/**
* Utility class containing help methods for the WS clients
* 
* @author Philip Vendil 28 okt 2007
*
* @version $Id: WSClientUtil.java,v 1.3 2007-12-12 14:00:07 herrvendil Exp $
*/
public class WSClientUtil {

	/**
	 * Method used to convert a coded SignRequestWS to a auto generated SignRequestWS
	 */
	public static List<ProcessRequestWS> convertProcessRequestWS( 
			List<org.signserver.protocol.ws.ProcessRequestWS> signRequestWS){
		List<ProcessRequestWS> retval = new ArrayList<ProcessRequestWS>();
		for (Iterator<org.signserver.protocol.ws.ProcessRequestWS> iterator = signRequestWS.iterator(); iterator.hasNext();) {
			org.signserver.protocol.ws.ProcessRequestWS next = iterator.next();
			ProcessRequestWS temp = new ProcessRequestWS();
			temp.setRequestDataBase64(next.getRequestDataBase64());
			retval.add(temp);
		}
		return retval;
	}
	
	/**
	 * Method used to convert a auto generated ProcessResponseWS to a coded ProcessResponseWS 
	 */
	public static List<org.signserver.protocol.ws.ProcessResponseWS> convertProcessResponseWS( 
			List<ProcessResponseWS> signResponseWS){
		List<org.signserver.protocol.ws.ProcessResponseWS> retval = new ArrayList<org.signserver.protocol.ws.ProcessResponseWS>();
		
		for (Iterator<ProcessResponseWS> iterator = signResponseWS.iterator(); iterator.hasNext();) {
			ProcessResponseWS next =  iterator.next();	
			org.signserver.protocol.ws.ProcessResponseWS temp = new org.signserver.protocol.ws.ProcessResponseWS();
			temp.setResponseDataBase64(next.getResponseDataBase64());
			retval.add(temp);
		}
		return retval;
	}

	/**
	 * Method to convert a auto generated Certificate to a coded WebService Certificate.
	 * @param signerCertificate
	 * @return
	 */
	/*
	private static org.signserver.protocol.ws.Certificate convertCertificate(
			org.signserver.protocol.ws.gen.Certificate certificate) {
		org.signserver.protocol.ws.Certificate retval = new  org.signserver.protocol.ws.Certificate();
		retval.setCertificateBase64(certificate.getCertificateBase64());
		return retval;
	}*/
	
}
