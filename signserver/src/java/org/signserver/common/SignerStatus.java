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

import java.security.cert.Certificate;

/**
 * Class used when responding to the SignSession.getStatus() method, represents
 * the status of a specific signer
 * @author Philip Vendil
 *
 * $Id: SignerStatus.java,v 1.1 2007-02-27 16:18:10 herrvendil Exp $
 */

public class SignerStatus extends WorkerStatus{

	public static final int STATUS_ACTIVE  = 1;
	public static final int STATUS_OFFLINE = 2;
	
	private static final long serialVersionUID = 1L;

	private int tokenStatus = 0;
	private Certificate signerCertificate = null;
	
	/** 
	 * Main constuctor
	 */
	public SignerStatus(int tokenStatus, SignerConfig config, Certificate signerCertificate){
		super(config);
		this.tokenStatus = tokenStatus;
	    this.signerCertificate = signerCertificate;
	}

	/**
	 * @return Returns the tokenStatus.
	 */
	public int getTokenStatus() {
		return tokenStatus;
	}

	 
	/**
	 * Method used to retrieve the currently used signercertficate.
	 * Use this method when checking status and not from config, since the cert isn't always in db.
	 * @return
	 */
	public Certificate getSignerCertificate(){
		return signerCertificate;
	}
		
	
}
