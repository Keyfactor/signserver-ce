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
package org.signserver.adminws;

/**
 * Representation of query ordering.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class QueryOrdering {
    
    public enum Order {
        ASC, DESC
    }

    private String column;
    private Order order;

    public QueryOrdering() {
    }
    
    public QueryOrdering(final String column, final Order order) {
        this.column = column;
        this.order = order;
    }

    public Order getOrder() {
        return order;
    }
    
    public String getColumn() {
        return column;
    }

    public void setColumn(String column) {
        this.column = column;
    }

    public void setOrder(Order order) {
        this.order = order;
    }

}
