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

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

import org.signserver.common.IProcessResponse;
import org.signserver.common.RequestAndResponseManager;

/**
 * ValidateResponse is the response sent back from the validation service
 * containing the status of the validation
 * 
 *
 * @author Philip Vendil
 * $Id: ValidateResponse.java,v 1.2 2007-12-11 05:37:52 herrvendil Exp $
 */
public class ValidateResponse implements IProcessResponse{
	private static final long serialVersionUID = 1L;

	private Validation validation;
	
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





	public void readExternal(ObjectInput in) throws IOException,
			ClassNotFoundException {
		in.readInt();
		validation = (Validation) in.readObject();
		
	}


	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(RequestAndResponseManager.RESPONSETYPE_VALIDATE);
		out.writeObject(validation);
	}


}
