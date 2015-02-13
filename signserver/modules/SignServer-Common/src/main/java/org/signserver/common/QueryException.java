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
import org.cesecore.util.query.clauses.Order;
import org.cesecore.util.query.elems.Operation;
import org.cesecore.util.query.elems.Term;

/**
 * Exception indicating that the query could not be finished successfully.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@WebFault
public class QueryException extends Exception {

    private static final long serialVersionUID = 1L;
    
    private Term offendingTerm;
    private Operation offendingOperation;
    private Order offendingOrder;
    
    public QueryException(String msg) {
        super(msg);
    }

    public QueryException(String message, Throwable cause) {
        super(message, cause);
    }

    public Term getOffendingTerm() {
        return offendingTerm;
    }

    public void setOffendingTerm(Term offendingTerm) {
        this.offendingTerm = offendingTerm;
    }

    public Operation getOffendingOperation() {
        return offendingOperation;
    }

    public void setOffendingOperation(Operation offendingOperation) {
        this.offendingOperation = offendingOperation;
    }

    public Order getOffendingOrder() {
        return offendingOrder;
    }

    public void setOffendingOrder(Order offendingOrder) {
        this.offendingOrder = offendingOrder;
    }
    
}
