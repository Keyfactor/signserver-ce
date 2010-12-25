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

package org.signserver.server.genericws.test;

import javax.jws.WebMethod;
import javax.jws.WebParam;

import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;

public interface IDummyWS {

	@WebMethod
	String test(@WebParam(name = "param1")
	String param1) throws IllegalRequestException, SignServerException;

}