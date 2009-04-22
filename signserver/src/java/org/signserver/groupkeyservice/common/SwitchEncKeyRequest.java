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
package org.signserver.groupkeyservice.common;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

import org.signserver.common.ProcessRequest;
import org.signserver.common.RequestAndResponseManager;

/**
 * SwitchEncKeyRequest is a process request sent to GroupKeyService in order to switch key 
 * used to encrypt the stored group keys in database.
 * 
 * @author Philip Vendil
 * $Id$
 */
public class SwitchEncKeyRequest extends ProcessRequest {
	
	private static final long serialVersionUID = 1L;
	// Not really used in this case.		

	
    /**
     * Default constructor used during serialization
     */
	public SwitchEncKeyRequest() {
	}



	public void parse(DataInput in) throws IOException {
		in.readInt();
	}




	public void serialize(DataOutput out) throws IOException {
		out.writeInt(RequestAndResponseManager.REQUESTTYPE_GKS_SWITCHENCKEY);
		
	}
	




}
