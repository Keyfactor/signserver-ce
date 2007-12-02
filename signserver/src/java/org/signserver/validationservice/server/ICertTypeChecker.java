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

package org.signserver.validationservice.server;

import org.signserver.common.WorkerConfig;
import org.signserver.validationservice.common.ICertificate;
import org.signserver.validationservice.common.ValidationServiceConstants;

/**
 * 
 * Interface used to check if a given certificate fulfills a specified 
 * certificate type.
 * 
 * @author Philip Vendil 1 dec 2007
 *
 * @version $Id: ICertTypeChecker.java,v 1.1 2007-12-02 20:35:17 herrvendil Exp $
 */

public interface ICertTypeChecker {
	
	void init(WorkerConfig config);
	
	/**
	 * Main method used to check that a certificate fulfills the 
	 * requirements of a specific certificate type
	 * 
	 * @param cert the certificate to check
	 * @param certType one of ValidationServiceConstants.CertType enum values
	 * @return true if the certificate fulfills the requirements otherwise false.
	 */
	boolean checkType(ICertificate cert, ValidationServiceConstants.CertType certType);

}
