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
package org.signserver.clientws;

import javax.xml.ws.WebFault;

/**
 * Representation of a failure likely caused by the client not providing a 
 * correct request or a request for an non-existing worker.
 * 
 * In case the request could not be processed typically because some error in 
 * the request data.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
@WebFault
public class RequestFailedException extends Exception {

    /**
     * Creates a new instance of
     * <code>RequestException</code> without detail message.
     */
    public RequestFailedException() {
    }

    /**
     * Constructs an instance of
     * <code>RequestException</code> with the specified detail message.
     *
     * @param msg the detail message.
     */
    public RequestFailedException(String msg) {
        super(msg);
    }
}
