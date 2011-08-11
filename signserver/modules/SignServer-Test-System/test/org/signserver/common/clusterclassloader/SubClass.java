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
import org.signserver.module.wsra.common.AuthorizationDeniedException;
import org.signserver.server.annotations.Transaction;

/**
 * TODO: Document me!
 * 
 * @version $Id$
 */
public class SubClass extends BaseClass implements FooInterface {

    public boolean haveRun = false;

    @Transaction
    public void revokeToken(@WebParam(name = "tokenSerialNumber") String tokenSerialNumber, @WebParam(name = "revocationReason") int reason) throws IllegalRequestException, SignServerException, AuthorizationDeniedException {

        if (tokenSerialNumber.equals("exception")) {
            throw new IllegalRequestException("Test");

        }
        haveRun = true;
        return;
    }

    @Override
    public boolean hasRun() {
        return haveRun;
    }

    /*
    public void foo(String arg) throws IOException {
    if(arg.equals("exception")){
    throw new IOException("Test");
    
    }
    haveRun = true;		
    return;
    
    }*/
}
