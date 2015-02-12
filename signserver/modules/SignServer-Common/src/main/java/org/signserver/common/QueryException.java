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

import javax.xml.ws.WebFault;
import org.cesecore.util.query.Elem;

/**
 * Exception indicating that the query could not be finished successfully.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@WebFault
public class QueryException extends Exception {

    private static final long serialVersionUID = 1L;
    
    private Elem offendingElement;
    
    public QueryException(String msg) {
        super(msg);
    }

    public QueryException(String message, Throwable cause) {
        super(message, cause);
    }
    
    public QueryException(String msg, Elem offendingElement) {
        super(msg);
        this.offendingElement = offendingElement;
    }

    public QueryException(String message, Throwable cause, Elem offendingElement) {
        super(message, cause);
        this.offendingElement = offendingElement;
    }

    public Elem getOffendingElement() {
        return offendingElement;
    }

    public void setOffendingElement(Elem offendingElement) {
        this.offendingElement = offendingElement;
    }

}
