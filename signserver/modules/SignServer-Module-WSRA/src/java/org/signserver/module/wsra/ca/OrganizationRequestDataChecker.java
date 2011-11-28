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
 
package org.signserver.module.wsra.ca;

import org.ejbca.util.CertTools;
import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.signserver.module.wsra.beans.UserDataBean;

/**
 * Class that checks that the request data contains and "O=" field, and
 * that the value of the O field is the same as the callers organization.
 * 	 
 * If not valid it will throw an IllegalRequeset exception.
 * 
 * 
 * @author Philip Vendil 25 okt 2008
 *
 * @version $Id$
 */

public class OrganizationRequestDataChecker extends BaseRequestDataChecker {

	/**
	 * Method that checks that the request data contains and "O=" field, and
	 * that the value of the O field is the same as the caller's organization's 
	 * display name.
	 * <p>
	 * If not valid it will throw an IllegalRequeset exception.
	 * @see org.signserver.module.wsra.ca.IRequestDataChecker#checkRequestData(org.signserver.module.wsra.beans.UserDataBean, org.signserver.module.wsra.ca.ICertRequestData, org.signserver.module.wsra.ca.ICertRequestData)
	 */
	public ICertRequestData checkRequestData(UserDataBean caller,
			ICertRequestData requestData, ICertRequestData importedData)
			throws IllegalRequestException, SignServerException {
		
		String subjectDN = requestData.getSubjectDN();
		if(subjectDN == null){
			throw new IllegalRequestException("Error: Subject DN in request cannot be null.");
		}
		
		String organization = CertTools.getPartFromDN(subjectDN, "O");
		if(organization == null){
			throw new IllegalRequestException("Error: Subject DN must contain a O (Organization) field.");
		}
		
		String callerOrganzation = db.om.findOrganization(caller.getOrganizationId()).getDisplayName();
		if(!organization.trim().equals(callerOrganzation.trim())){
			throw new IllegalRequestException("Error: Subject DN contains an illegal organization field, request organization field is '" + organization + "' and allowed value is '" + callerOrganzation + "'.");
		}
		return requestData;
	}
	

}
