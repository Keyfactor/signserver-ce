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
 
package org.signserver.module.wsra.common.authtypes;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.ejbca.util.CertTools;
import org.signserver.common.RequestContext;

/**
 * And authentication type matcher that checks
 * the issuer DN and certificate serial number of the requests
 * client certificate.
 * 
 * 
 * @author Philip Vendil 12 okt 2008
 *
 * @version $Id$
 */

public class CertSNAuthType implements IAuthType{

	private static final int AUTH_TYPE = 2;

	/**
	 * @see org.signserver.module.wsra.common.authtypes.IAuthType#getAuthType()
	 */
	public int getAuthType() {
		return AUTH_TYPE;
	}

	/**
	 * Builds matchvalue from "<issuerDN>;<cert serial (decimal)>"
	 * 
	 * @see org.signserver.module.wsra.common.authtypes.IAuthType#getMatchValue(RequestContext)
	 */
	public String getMatchValue(RequestContext requestContext) {
	    String retval = null;
		if(requestContext.get(RequestContext.CLIENT_CERTIFICATE) != null){
			X509Certificate cert = (X509Certificate) requestContext.get(RequestContext.CLIENT_CERTIFICATE);
			return CertTools.getIssuerDN(cert) + ";" + cert.getSerialNumber().toString();
			
		}
		
		return retval;
	}
	
	/**
	 * Method used to calculate a match value from a
	 * issuerDN and certificate serial number.
	 */
	public String getMatchValue(String issuerDN, BigInteger certSerialNumber) {
		return CertTools.stringToBCDNString(issuerDN) + ";" + certSerialNumber.toString();		
	}

}
