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
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;
import org.signserver.validationservice.server.ICertificateManager;

/**
 * Base validation VO containing the status of a specific certificate.
 * 
 * It's main field is 'status' containing one of the status constants.
 * 
 * 
 * @author Philip Vendil 26 nov 2007
 *
 * @version $Id: Validation.java,v 1.2 2007-12-02 20:35:17 herrvendil Exp $
 */

public class Validation implements Serializable{
	
	private transient Logger log = Logger.getLogger(this.getClass());
		
	private static final long serialVersionUID = 1L;
	
	public enum    Status{VALID,
		                  REVOKED,
		                  NOTYETVALID,
		                  EXPIRED,
		                  DONTVERIFY,
		                  CAREVOKED,
		                  CANOTYETVALID,
		                  CAEXPIRED,
		                  BADCERTTYPE		
	};

	
	private transient ICertificate certificate;
	private byte[] certificateData;
	private transient List<ICertificate> cAChain;
	private List<byte[]> cAChainData;
	private Status status;
	private String statusMessage;
	private Date validationDate;
	private Date revokedDate;
	private int revokationReason = 0;
	
	/**
	 * Constructor that should be used for validation that resulted in
	 * a not revoked status.
	 * 
	 * @param certificate the certificate that have been validated.
	 * @param cAChain the CA certificate chain with the root CA last.
	 * @param status one of the STATUS_ constants defining the status of the certificate.
	 * @param statusMessage human readable status message of the validation.
	 */
	public Validation(ICertificate certificate, List<ICertificate> cAChain, Status status,
			String statusMessage) {
		this(certificate, cAChain, status, statusMessage, null, 0);

	}

	/**
	 * Constructor that should be used for validation that resulted in
	 * a revoked status.
	 * 
	 * @param certificate the certificate that have been validated.
	 * @param cAChain the CA certificate chain with the root CA last.
	 * @param status one of the STATUS_ constants defining the status of the certificate.
	 * @param statusMessage human readable status message of the validation.
	 * @param revokedDate null if not revoked.
	 * @param revokationReason one of the reasons specified in RFC3280, 0 if not revoked.
	 */
	public Validation(ICertificate certificate, List<ICertificate> cAChain, Status status,
			String statusMessage, Date revokedDate, int revokationReason) {
		super();
		this.validationDate = new Date();
		this.certificate = certificate;
		this.cAChain = cAChain;
		this.status = status;
		this.statusMessage = statusMessage;
		this.revokedDate = revokedDate;
		this.revokationReason = revokationReason;
		try {
			this.certificateData = certificate.getEncoded();

			if(cAChain != null){
				this.cAChainData = new ArrayList<byte[]>();
				for(ICertificate cert : cAChain){
					cAChainData.add(0,cert.getEncoded());
				}
			}
		} catch (CertificateEncodingException e) {
			log.error(e);
		}
	}

	/**
	 * @return the certificate that have been validated.
	 */
	public ICertificate getCertificate() {
		if(certificate == null){
			try {
				certificate = ICertificateManager.genICertificate(CertTools.getCertfromByteArray(certificateData));
			} catch (CertificateException e) {
				log.error(e);
			}
		}
		return certificate;
	}

	/**
	 * @return the status, one of the STATUS_ constants defining the status of the certificate.
	 */
	public Status getStatus() {
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

	/**
	 * @return the CA certificate chain with the root CA last.
	 */
	public List<ICertificate> getCAChain() {
		if(cAChain == null && cAChainData != null){
			cAChain = new ArrayList<ICertificate>();
			for (byte[] certData : cAChainData){
				try {
					ICertificate cACert = ICertificateManager.genICertificate(CertTools.getCertfromByteArray(certData));
					cAChain.add(0,cACert);
				} catch (CertificateException e) {
					log.error(e);
				}				
			}
		}
		return cAChain;
	}

	/**
	 * @return the validationDate of when the validation was performed.
	 */
	public Date getValidationDate() {
		return validationDate;
	}

	

}
