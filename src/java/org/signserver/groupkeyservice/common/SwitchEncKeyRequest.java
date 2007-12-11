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

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

import org.signserver.common.IProcessRequest;
import org.signserver.common.RequestAndResponseManager;

/**
 * SwitchEncKeyRequest is a process request sent to GroupKeyService in order to switch key 
 * used to encrypt the stored group keys in database.
 * 
 * @author Philip Vendil
 * $Id: SwitchEncKeyRequest.java,v 1.2 2007-12-11 05:36:58 herrvendil Exp $
 */
public class SwitchEncKeyRequest implements IProcessRequest {
	
	private static final long serialVersionUID = 1L;
	// Not really used in this case.		

	
    /**
     * Default constructor used during serialization
     */
	public SwitchEncKeyRequest() {
	}




	public void readExternal(ObjectInput in) throws IOException,
			ClassNotFoundException {
		in.readInt();
		
	}

	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(RequestAndResponseManager.REQUESTTYPE_GKS_SWITCHENCKEY);
		
	}
	




}
