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
public class AuditlogOperator {
    
    private static final HashMap<RelationalOperator, AuditlogOperator> ENTRIES = new HashMap<RelationalOperator, AuditlogOperator>();
    
    static {
        ENTRIES.put(RelationalOperator.BETWEEN, new AuditlogOperator(RelationalOperator.BETWEEN, "Between"));
        ENTRIES.put(RelationalOperator.EQ, new AuditlogOperator(RelationalOperator.EQ, "Equals"));
        ENTRIES.put(RelationalOperator.GE, new AuditlogOperator(RelationalOperator.GE, "Greater or equals"));
        ENTRIES.put(RelationalOperator.GT, new AuditlogOperator(RelationalOperator.GT, "Greater than"));
        ENTRIES.put(RelationalOperator.LE, new AuditlogOperator(RelationalOperator.LE, "Lesser or equals"));
        ENTRIES.put(RelationalOperator.LIKE, new AuditlogOperator(RelationalOperator.LIKE, "Like"));
        ENTRIES.put(RelationalOperator.LT, new AuditlogOperator(RelationalOperator.LT, "Lesser than"));
        ENTRIES.put(RelationalOperator.NEQ, new AuditlogOperator(RelationalOperator.NEQ, "Not equals"));
        ENTRIES.put(RelationalOperator.NOTNULL, new AuditlogOperator(RelationalOperator.NOTNULL, "Is not null"));
        ENTRIES.put(RelationalOperator.NULL, new AuditlogOperator(RelationalOperator.NULL, "Is null"));
    }
    
    private RelationalOperator operator;
    private String description;
    
    public static AuditlogOperator fromEnum(RelationalOperator op) {
        return ENTRIES.get(op);
    }
    
    public AuditlogOperator(RelationalOperator operator, String description) {
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

    public static AuditlogOperator[] getColumns() {
        return ENTRIES.values().toArray(new AuditlogOperator[0]);
    }
    
}
