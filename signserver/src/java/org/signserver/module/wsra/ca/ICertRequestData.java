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
 
package org.signserver.module.wsra.ca;

import java.security.PublicKey;


/**
 * Interface that all certificate request data value
 * objects should implement.
 * 
 * 
 * @author Philip Vendil 18 okt 2008
 *
 * @version $Id$
 */

public interface ICertRequestData {
	
	/**
	 * The type of certificate.
	 * 
	 * @return the type of certificate, could be certificate profile or template
	 * the actual value is up to the ICAConnector implementation/configuration to 
	 * decide.
	 */
	String getCertificateProfile();
	
	/**
	 * The subject DN or equivalent that should be used in certificate.
	 * 
	 * @return The subject DN or equivalent that should be used in certificate.
	 * Never null.
	 */
	String getSubjectDN();
	
	/**
	 * 
	 * @return the subject alternative name that should be used. 
	 * return null if no subject alternative name should be used.
	 */
	String getSubjectAltName();
	
	/**
	 * 
	 * @return the public key that should be certified.
	 */
	PublicKey getPublicKey();
	
	/**
	 * 
	 * @return DN of the issuer that should certify the request
	 */
	String getIssuerDN();

}
