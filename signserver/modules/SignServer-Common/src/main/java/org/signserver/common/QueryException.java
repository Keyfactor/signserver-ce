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
package org.signserver.common;

import jakarta.xml.ws.WebFault;

/**
 * Exception indicating that the query could not be finished successfully.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@WebFault
public class QueryException extends Exception {

    private static final long serialVersionUID = 1L;
    
    public QueryException(String msg) {
        super(msg);
    }

    public QueryException(String message, Throwable cause) {
        super(message, cause);
    }

}
