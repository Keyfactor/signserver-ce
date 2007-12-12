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

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

import org.signserver.common.ProcessResponse;
import org.signserver.common.RequestAndResponseManager;

/**
 * ValidateResponse is the response sent back from the validation service
 * containing the status of the validation
 * 
 *
 * @author Philip Vendil
 * $Id: ValidateResponse.java,v 1.3 2007-12-12 14:00:07 herrvendil Exp $
 */
public class ValidateResponse extends ProcessResponse{
	private static final long serialVersionUID = 1L;

	private transient Validation validation;
	
    /**
     * Default constructor used during serialization
     */
	public ValidateResponse(){}
	
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
	 * @return The validation of the requested certificate
	 */
	public Validation getValidation() {
		return validation;
	}


	public void parse(DataInput in) throws IOException {
		in.readInt();
		validation = new Validation();
		validation.parse(in);
	}

	public void serialize(DataOutput out) throws IOException {
		out.writeInt(RequestAndResponseManager.RESPONSETYPE_VALIDATE);
		validation.serialize(out);		
	}


}
