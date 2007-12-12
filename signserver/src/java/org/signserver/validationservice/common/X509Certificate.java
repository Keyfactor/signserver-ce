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

import java.security.cert.CertificateParsingException;

import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.ejbca.util.CertTools;


/**
 * ValidationService implementation of a X509Certificate.
 * The only difference is the implementation of the
 * 
 * 
 * @author Philip Vendil 29 nov 2007
 *
 * @version $Id: X509Certificate.java,v 1.2 2007-12-12 15:13:37 herrvendil Exp $
 */
@SuppressWarnings("unchecked")
public class X509Certificate extends X509CertificateObject
		implements ICertificate {

	private static final long serialVersionUID = 1L;

	public X509Certificate(X509CertificateStructure certificateStructure) throws CertificateParsingException{
		super(certificateStructure);		
	}

	public String getIssuer() {		
		return CertTools.getIssuerDN(this);
	}

	public String getSubject() {
		return CertTools.getSubjectDN(this);
	}




}
