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
 

package org.signserver.rmi;

import java.rmi.RemoteException;

/**
 * @author lars
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class TryAgainException extends RemoteException {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
     * 
     */
    public TryAgainException() {
        super();
        // TODO Auto-generated constructor stub
    }

    /**
     * @param s
     */
    public TryAgainException(String s) {
        super(s);
        // TODO Auto-generated constructor stub
    }

    /**
     * @param s
     * @param cause
     */
    public TryAgainException(String s, Throwable cause) {
        super(s, cause);
        // TODO Auto-generated constructor stub
    }

}
