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

import org.signserver.common.IProcessResponse;

/**
 * ValidateResponse is the response sent back from the validation service
 * containing the status of the validation
 * 
 *
 * @author Philip Vendil
 * $Id: ValidateResponse.java,v 1.1 2007-12-02 20:35:17 herrvendil Exp $
 */
public class ValidateResponse implements IProcessResponse{
	private static final long serialVersionUID = 1L;

	private Validation validation;
	
	/**
	 * Main constructor
	 * 
	 * @param validations of the certificate verified.
	 */
	public ValidateResponse(Validation validation) {
		super();
		this.validation = validation;
	}

	/**
	 * Not supported method.
	 */
	public Serializable getProcessedData() {
		return null;
	}



	/**
	 * @return The validation of the requested certificate
	 */
	public Validation getValidation() {
		return validation;
	}


}
