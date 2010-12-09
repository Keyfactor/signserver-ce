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

package org.signserver.client.api;

/**
 * Tests for client API with a CRLValidator and uses the web services interface.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class SigningAndValidationWithCRLUsingWSTest extends SigningAndValidationWithCRLTest {

	@Override
	protected ISigningAndValidation getSigningAndValidationImpl() {
		return new SigningAndValidationWS("localhost", 
                        getPublicHTTPPort());
	}
		
}
