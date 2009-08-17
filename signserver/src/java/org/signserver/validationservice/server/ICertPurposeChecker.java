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

/**
 * 
 * Interface used to check if a given certificate fulfills a specified 
 * certificate type.
 * 
 * @author Philip Vendil 1 dec 2007
 *
 * @version $Id$
 */

public interface ICertPurposeChecker {
	
	void init(WorkerConfig config);
	
	/**
	 * Main method used to check that a certificate fulfills the 
	 * requirements of a specific certificate type
	 * 
	 * @param cert the certificate to check
	 * @param certPurposes one of ValidationServiceConstants.CERTPURPOSE_ constants or other custom defined.
	 * @return a subset of fullfilled certificate purposes or NULL if no purposes were valid.
	 */
	String[] checkCertPurposes(ICertificate cert, String[] certPurposes);

}
