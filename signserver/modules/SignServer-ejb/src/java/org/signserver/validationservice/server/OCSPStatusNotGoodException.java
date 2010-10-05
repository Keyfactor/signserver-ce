package org.signserver.validationservice.server;

import org.signserver.common.SignServerException;

public class OCSPStatusNotGoodException extends SignServerException {

	private static final long serialVersionUID = 1L;
	
	private Object certStatus;

	public void setCertStatus(Object certStatus) {
		this.certStatus = certStatus;
	}

	public Object getCertStatus() {
		return certStatus;
	}

	public OCSPStatusNotGoodException(String message, Object certStatus) {
		super(message);
		this.certStatus = certStatus;
	}
	
	public OCSPStatusNotGoodException(String message, Throwable e, Object certStatus) {
		super(message,e);
		this.certStatus = certStatus;
	}
	
	public String getMessage() {
		return super.getMessage();		
	}
}
