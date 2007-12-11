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
import java.util.ArrayList;
import java.util.List;

import org.signserver.common.RequestAndResponseManager;

/**
 * Class containing info about the remove group keys request
 * with document id specification.
 * 
 * 
 * @author Philip Vendil 13 nov 2007
 *
 * @version $Id: DocumentIDRemoveGroupKeyRequest.java,v 1.2 2007-12-11 05:36:58 herrvendil Exp $
 */
public class DocumentIDRemoveGroupKeyRequest implements IRemoveGroupKeyRequest {

	private static final long serialVersionUID = 1L;
	
	
	private List<String> documentIds;
	
    /**
     * Default constructor used during serialization
     */
	public DocumentIDRemoveGroupKeyRequest(){}
	
    /**
     * 
     * @param documentIds list of document ids to remove
     */
	public DocumentIDRemoveGroupKeyRequest(List<String> documentIds) {
		super();
		this.documentIds = documentIds;
	}


	/**
	 * @return list of document ids to remove
	 */
	public List<String> getDocumentIds() {
		return documentIds;
	}




	public void readExternal(ObjectInput in) throws IOException,
			ClassNotFoundException {
		in.readInt();
		int size = in.readInt();
		this.documentIds = new ArrayList<String>();
		for(int i=0;i<size;i++){
			int stringLen = in.readInt();
			byte[] stringData = new byte[stringLen];
			in.readFully(stringData);
			documentIds.add(new String(stringData,"UTF-8"));
		}		
	}


	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeInt(RequestAndResponseManager.REQUESTTYPE_GKS_IDREMKEYS);
		out.writeInt(documentIds.size());
		for(String documentId : documentIds){
			byte[] stringData = documentId.getBytes("UTF-8");
			out.writeInt(stringData.length);
			out.write(stringData);
		}		
	}



}
