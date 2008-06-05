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

package org.signserver.validationservice.server;

import java.security.cert.X509Certificate;

import org.signserver.common.WorkerConfig;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.ValidationServiceConstants;

/**
 * Default Certificate Type Checker used check the key usage against 
 * standard X509 V3 certificates.
 * 
 * 
 * @author Philip Vendil 1 dec 2007
 *
 * @version $Id: DefaultX509CertTypeChecker.java,v 1.1 2007-12-02 20:35:17 herrvendil Exp $
 */

public class DefaultX509CertTypeChecker implements ICertTypeChecker {

	/**
	 * Does the following checks
	 * <p>
	 * If the certificate have certType : IDENTIFICATION it checks for
	 * key usages digital signature and key encipherment
	 * </p>
	 * <p>
	 * If the certificate have certType : ELECTRONIC_SIGNATURE it checks for
	 * key usage non-repudiation
	 * </p>
	 * @see org.signserver.validationservice.server.ICertTypeChecker#checkType(org.signserver.validationservice.common.ICertificate, org.signserver.validationservice.common.ValidationServiceConstants.CertType)
	 */
	public boolean checkType(ICertificate cert, String certType) {
		boolean retval = false;
		
		if(cert instanceof java.security.cert.X509Certificate){
			java.security.cert.X509Certificate c = (X509Certificate) cert;
			if(certType.equalsIgnoreCase(ValidationServiceConstants.CERTTYPE_ANY)){
				retval = true;
			}else if (certType.equalsIgnoreCase(ValidationServiceConstants.CERTTYPE_IDENTIFICATION)){
				retval = c.getKeyUsage() != null  && c.getKeyUsage()[0] == true && c.getKeyUsage()[2] == true;				
			}else if (certType.equalsIgnoreCase(ValidationServiceConstants.CERTTYPE_ELECTRONIC_SIGNATURE)){
				retval = c.getKeyUsage() != null  && c.getKeyUsage()[1] == true;
			}
		}
		return retval;
	}

	/**
	 * @see org.signserver.validationservice.server.ICertTypeChecker#init(org.signserver.common.WorkerConfig)
	 */
	public void init(WorkerConfig config) {
		// Not used
	}

}
