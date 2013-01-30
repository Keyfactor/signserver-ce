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

import org.cesecore.util.query.elems.RelationalOperator;

/**
 * Representation of an query condition.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class QueryCondition {
    private String column;
    private RelationalOperator operator;
    private String value;

    public QueryCondition() {
    }
    
    public QueryCondition(String column, RelationalOperator operator, String value) {
        this.column = column;
        this.operator = operator;
        this.value = value;
    }

    public String getColumn() {
        return column;
    }

    public RelationalOperator getOperator() {
        return operator;
    }

    public String getValue() {
        return value;
    }

    public void setColumn(String column) {
        this.column = column;
    }

    public void setOperator(RelationalOperator operator) {
        this.operator = operator;
    }

    public void setValue(String value) {
        this.value = value;
    }
    
}
