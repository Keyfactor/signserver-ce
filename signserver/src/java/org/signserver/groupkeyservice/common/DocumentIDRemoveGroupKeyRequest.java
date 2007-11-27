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

import java.util.List;

/**
 * Class containing info about the remove group keys request
 * with document id specification.
 * 
 * 
 * @author Philip Vendil 13 nov 2007
 *
 * @version $Id: DocumentIDRemoveGroupKeyRequest.java,v 1.1 2007-11-27 06:05:05 herrvendil Exp $
 */
public class DocumentIDRemoveGroupKeyRequest implements IRemoveGroupKeyRequest {

	private static final long serialVersionUID = 1L;
	
	
	private List<String> documentIds;
	
	
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



}
