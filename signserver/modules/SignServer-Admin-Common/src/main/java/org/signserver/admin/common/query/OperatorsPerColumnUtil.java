// XXX: Duplicated from AddConditionDialog.java
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
package org.signserver.admin.common.query;

import org.cesecore.util.query.elems.RelationalOperator;

/**
 *
 * @version $Id$
 */
public class OperatorsPerColumnUtil {
    
    /** Relational operators useful for text values. */
    public static final QueryOperator[] TEXT_OPERATORS = {
        QueryOperator.fromEnum(RelationalOperator.EQ),
        QueryOperator.fromEnum(RelationalOperator.LIKE),
        QueryOperator.fromEnum(RelationalOperator.NEQ),
        QueryOperator.fromEnum(RelationalOperator.NOTNULL),
        QueryOperator.fromEnum(RelationalOperator.NULL)
    };
    
    /** Relational operators useful for fixed-type values. */
    public static final QueryOperator[] TYPE_OPERATORS = {
        QueryOperator.fromEnum(RelationalOperator.EQ),
        QueryOperator.fromEnum(RelationalOperator.NEQ)
    };
    
    /** Relational operators useful for number values. */
    public static final QueryOperator[] NUMBER_OPERATORS = {
        QueryOperator.fromEnum(RelationalOperator.EQ),
        QueryOperator.fromEnum(RelationalOperator.NEQ),
        QueryOperator.fromEnum(RelationalOperator.GE),
        QueryOperator.fromEnum(RelationalOperator.GT),
        QueryOperator.fromEnum(RelationalOperator.LE),
        QueryOperator.fromEnum(RelationalOperator.LT),
        QueryOperator.fromEnum(RelationalOperator.NOTNULL),
        QueryOperator.fromEnum(RelationalOperator.NULL)
    };
    
    public static QueryOperator[] getOperatorsForColumn(final QueryColumn column) {
        switch (column.getType()) {
            case TEXT:
                return TEXT_OPERATORS;
            case NUMBER:
            case TIME:
                return NUMBER_OPERATORS;
            case TYPE:
                return TYPE_OPERATORS;
            default:
                throw new IllegalArgumentException("Unknown column type");
        }
    }
    
}
