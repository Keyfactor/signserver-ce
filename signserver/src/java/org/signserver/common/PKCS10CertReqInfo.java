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

package org.signserver.common;

import org.bouncycastle.asn1.ASN1Set;

/**
 * Class containing information needed to for a signer to create
 * a PKCS10 certificate request, contains the subject dn 
 * and ASN1 set of extensions
 * 
 * 
 * @author Philip Vendil 2007 feb 19
 *
 * @version $Id$
 */

public class PKCS10CertReqInfo implements ISignerCertReqInfo {

	private static final long serialVersionUID = 1L;
	private String   signatureAlgorithm = null;
    private String subjectDN = null;
    private ASN1Set attributes = null;
    
    /**
     * @param signatureAlgorithm used to sign the PKCS10
     * @param subjectDN used in the request
     * @param attributes might be null
     */	
	public PKCS10CertReqInfo(String signatureAlgorithm, String subjectDN, ASN1Set attributes) {
		super();
		this.signatureAlgorithm = signatureAlgorithm;
		this.subjectDN = subjectDN;
		this.attributes = attributes;
	}

	/**
	 * 
	 * @return used to sign the PKCS10
	 */
	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}
	
	/**
	 *
	 * @return used in the request
	 */
	public String getSubjectDN() {
		return subjectDN;
	}
	
	/**
	 * @return attributes, might be null
	 */
	public ASN1Set getAttributes() {
		return attributes;
	}
}
