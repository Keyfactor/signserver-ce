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
package org.signserver.admin.gui;

import java.util.HashMap;
import org.signserver.admin.gui.adminws.gen.RelationalOperator;


/**
 * Representation of an relational operator.
 * 
 * TODO: Refactor using enum.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class QueryOperator {
    
    private static final HashMap<RelationalOperator, QueryOperator> ENTRIES = new HashMap<RelationalOperator, QueryOperator>();
    
    static {
        ENTRIES.put(RelationalOperator.BETWEEN, new QueryOperator(RelationalOperator.BETWEEN, "Between"));
        ENTRIES.put(RelationalOperator.EQ, new QueryOperator(RelationalOperator.EQ, "Equals"));
        ENTRIES.put(RelationalOperator.GE, new QueryOperator(RelationalOperator.GE, "Greater or equals"));
        ENTRIES.put(RelationalOperator.GT, new QueryOperator(RelationalOperator.GT, "Greater than"));
        ENTRIES.put(RelationalOperator.LE, new QueryOperator(RelationalOperator.LE, "Lesser or equals"));
        ENTRIES.put(RelationalOperator.LIKE, new QueryOperator(RelationalOperator.LIKE, "Like"));
        ENTRIES.put(RelationalOperator.LT, new QueryOperator(RelationalOperator.LT, "Lesser than"));
        ENTRIES.put(RelationalOperator.NEQ, new QueryOperator(RelationalOperator.NEQ, "Not equals"));
        ENTRIES.put(RelationalOperator.NOTNULL, new QueryOperator(RelationalOperator.NOTNULL, "Is not null"));
        ENTRIES.put(RelationalOperator.NULL, new QueryOperator(RelationalOperator.NULL, "Is null"));
    }
    
    private RelationalOperator operator;
    private String description;
    
    public static QueryOperator fromEnum(RelationalOperator op) {
        return ENTRIES.get(op);
    }
    
    public QueryOperator(RelationalOperator operator, String description) {
        this.operator = operator;
        this.description = description;
    }

    public RelationalOperator getOperator() {
        return operator;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return description + " (" + operator + ")";
    }

    public static QueryOperator[] getColumns() {
        return ENTRIES.values().toArray(new QueryOperator[0]);
    }
    
}
