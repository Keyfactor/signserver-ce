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

import java.security.cert.Certificate;
import java.util.Date;

/**
 * Base validation VO containing the status of a specific certificate.
 * 
 * It's main field is 'status' containing one of the status constants.
 * 
 * 
 * @author Philip Vendil 26 nov 2007
 *
 * @version $Id: Validation.java,v 1.1 2007-11-27 06:05:13 herrvendil Exp $
 */

public class Validation {
		
	public static final String STATUS_VALID       = "VALID";
	public static final String STATUS_REVOKED     = "REVOKED";
	public static final String STATUS_NOTYETVALID = "NOTYETVALID";
	public static final String STATUS_EXPIRED     = "EXPIRED";
	public static final String STATUS_DONTVERIFY  = "DONTVERIFY";

	private Certificate certificate;
	private String status;
	private String statusMessage;
	private Date revokedDate;
	private int revokationReason = 0;
	
	/**
	 * Constructor that should be used for validation that resulted in
	 * a not revoked status.
	 * 
	 * @param certificate the certificate that have been validated.
	 * @param status one of the STATUS_ constants defining the status of the certificate.
	 * @param statusMessage human readable status message of the validation.
	 */
	public Validation(Certificate certificate, String status,
			String statusMessage) {
		super();
		this.certificate = certificate;
		this.status = status;
		this.statusMessage = statusMessage;
	}

	/**
	 * Constructor that should be used for validation that resulted in
	 * a revoked status.
	 * 
	 * @param certificate the certificate that have been validated.
	 * @param status one of the STATUS_ constants defining the status of the certificate.
	 * @param statusMessage human readable status message of the validation.
	 * @param revokedDate null if not revoked.
	 * @param revokationReason one of the reasons specified in RFC3280, 0 if not revoked.
	 */
	public Validation(Certificate certificate, String status,
			String statusMessage, Date revokedDate, int revokationReason) {
		super();
		this.certificate = certificate;
		this.status = status;
		this.statusMessage = statusMessage;
		this.revokedDate = revokedDate;
		this.revokationReason = revokationReason;
	}

	/**
	 * @return the certificate that have been validated.
	 */
	public Certificate getCertificate() {
		return certificate;
	}

	/**
	 * @return the status, one of the STATUS_ constants defining the status of the certificate.
	 */
	public String getStatus() {
		return status;
	}

	/**
	 * @return the statusMessage, human readable status message of the validation.
	 */
	public String getStatusMessage() {
		return statusMessage;
	}

	/**
	 * @return the revokedDate, null if not revoked.
	 */
	public Date getRevokedDate() {
		return revokedDate;
	}

	/**
	 * @return the revokationReason, one of the reasons specified in RFC3280, 0 if not revoked.
	 */
	public int getRevokationReason() {
		return revokationReason;
	}

	

}
