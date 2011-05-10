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

import java.security.cert.X509Certificate;

import org.ejbca.util.CertTools;
import org.signserver.common.RequestContext;

/**
 * And authentication type matcher that checks
 * the isserDN and serial number field in DN of the requests
 * client certificate.
 * 
 * 
 * @author Philip Vendil 12 okt 2008
 *
 * @version $Id$
 */

public class SNinDNAuthType implements IAuthType{

	private static final int AUTH_TYPE = 3;

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
			String dn = CertTools.getSubjectDN(cert);
			String sn = CertTools.getPartFromDN(dn, "SN");
			if(sn == null){
				sn = CertTools.getPartFromDN(dn, "SERIALNUMBER");
			}
			if(sn != null){
			  return CertTools.getIssuerDN(cert) + ";" + sn;
			}
			
		}
		
		return retval;
	}
	
	/**
	 * Method used to calculate a match value from a
	 * issuerDN and serial number.
	 */
	public String getMatchValue(String issuerDN, String serialNumberInDN) {
		return CertTools.stringToBCDNString(issuerDN) + ";" + serialNumberInDN;		
	}

}
