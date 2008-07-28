package org.signserver.validationservice.server;

import org.signserver.common.SignServerException;

public class CRLCertRevokedException extends SignServerException {

	private static final long serialVersionUID = 1L;
	
	private int reasonCode;

	public void setReasonCode(int reasonCode) {
		this.reasonCode = reasonCode;
	}

	public int getReasonCode() {
		return reasonCode;
	}

	public CRLCertRevokedException(String message, int reasonCode) {
		super(message);
		this.reasonCode = reasonCode;
	}
	
	public CRLCertRevokedException(String message, Throwable e, int reasonCode) {
		super(message,e);
		this.reasonCode = reasonCode;
	}
	
	public String getMessage() {
		return super.getMessage();		
	}
}
