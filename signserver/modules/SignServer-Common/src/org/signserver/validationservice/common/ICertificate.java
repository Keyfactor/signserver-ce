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

package org.signserver.validationservice.common;

import java.io.Serializable;
import java.security.cert.CertificateEncodingException;

/**
 * Special certificate interface used to let validation services support
 * other kinds of certificates that just X509Certificates.
 * 
 * Extends the regular Certificate interface with two methods
 * getSubject : which should return a unique subject string
 * getIssuer  : which should return a unique issuer string
 * 
 * 
 * @author Philip Vendil 29 nov 2007
 *
 * @version $Id$
 */

public interface ICertificate extends Serializable{
	
	/**
	 * 
	 * @return a unique subject string identifying the owner, never null. 
	 */
	String getSubject();
	
	/**
	 * 
	 * @return @return a unique subject string identifying the issuer, never null.
	 */
	String getIssuer();

	/**
	 * Method that should return this certificate i byte array format.
	 */
	byte[] getEncoded() throws CertificateEncodingException;

}
