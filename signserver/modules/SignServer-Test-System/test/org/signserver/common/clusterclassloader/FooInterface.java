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
package org.signserver.common.clusterclassloader;

import javax.jws.WebParam;

import org.signserver.common.IllegalRequestException;
import org.signserver.common.SignServerException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public interface FooInterface {
    //void foo(String arg) throws IOException;

    public void revokeToken(@WebParam(name = "tokenSerialNumber") String tokenSerialNumber, @WebParam(name = "revocationReason") int reason) throws IllegalRequestException, SignServerException, AuthorizationDeniedException;

    boolean hasRun();
}
