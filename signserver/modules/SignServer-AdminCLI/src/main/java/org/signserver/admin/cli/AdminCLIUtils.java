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
package org.signserver.admin.cli;

import java.util.List;
import java.util.Set;

import org.cesecore.util.ValidityDate;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.Elem;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;

/**
 * Utility functions for managing
 * query criteria for querying audit log
 * and archive data.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 *
 */
public class AdminCLIUtils {

    public static Term parseCriteria(final String criteria, 
            final Set<String> allowedFields, final Set<RelationalOperator> noArgOps,
            final Set<String> intFields, final Set<String> longFields, final Set<String> dateFields)
                    throws IllegalArgumentException, NumberFormatException, java.text.ParseException {
        // find an operator
        final String[] parts = criteria.split(" ", 3);
        
        final String field = parts[0];
        final RelationalOperator op = RelationalOperator.valueOf(parts[1]);
        Object value = null;
        
        // we will not handle the BETWEEN operator
        // to avoid complicating the parser, the same
        // result can be achieved with two criterias
        if (op == RelationalOperator.BETWEEN) {
            throw new IllegalArgumentException("Operator BETWEEN is not supported");
        }
        
        if (!allowedFields.contains(field)) {
            throw new IllegalArgumentException("Unrecognized field: " + field);
        }
        
        if (!noArgOps.contains(op)) {
            if (intFields.contains(parts[0])) {
                value = Integer.parseInt(parts[2]);
            } else if (longFields.contains(parts[0])) {
                value = Long.parseLong(parts[2]);
            } else if (dateFields.contains(parts[0])) {
                try {
                    value = Long.parseLong(parts[2]);
                } catch (NumberFormatException e) {
                    value = ValidityDate.parseAsIso8601(parts[2]).getTime();
                }
            } else {
                if (parts.length < 3) {
                    throw new IllegalArgumentException("Missing value");
                }
                value = parts[2];
            }
        }
        
        return new Term(op, field, value);
    }
    
    public static Elem andAll(final List<Elem> elements, final int index) {
        if (index >= elements.size() - 1) {
            return elements.get(index);
        } else {
            return Criteria.and(elements.get(index), andAll(elements, index + 1));
        }
    }
    
}
