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

import java.text.ParseException;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.cesecore.audit.AuditLogEntry;

import org.cesecore.util.ValidityDate;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.Elem;
import org.cesecore.util.query.elems.RelationalOperator;
import org.cesecore.util.query.elems.Term;
import org.signserver.common.ArchiveMetadata;
import static org.signserver.common.SignServerConstants.TOKEN_ENTRY_FIELDS_ALIAS;
import static org.signserver.common.SignServerConstants.TOKEN_ENTRY_FIELDS_KEY_ALIAS;

/**
 * Utility functions for managing
 * query criteria for querying audit log
 * and archive data.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class QueryUtil {

    private static final HashSet<String> LONG_COLUMNS = new HashSet<>();
    private static final HashSet<String> INT_COLUMNS = new HashSet<>();
    
    static {
        LONG_COLUMNS.add(AuditLogEntry.FIELD_TIMESTAMP);
        LONG_COLUMNS.add(AuditLogEntry.FIELD_SEQUENCENUMBER);
        LONG_COLUMNS.add(ArchiveMetadata.TIME);
        INT_COLUMNS.add(ArchiveMetadata.SIGNER_ID);
        INT_COLUMNS.add(ArchiveMetadata.TYPE);
    }

    public static Term parseCriteria(final String criteria, 
            final Set<String> allowedFields, final Set<RelationalOperator> noArgOps,
            final Set<String> intFields, final Set<String> longFields, final Set<String> dateFields)
                    throws IllegalArgumentException, NumberFormatException, ParseException {
        // find an operator
        final String[] parts = criteria.split(" ", 3);

        String field = parts[0];
        
        if (parts.length < 2) {
            throw new IllegalArgumentException("Missing operator");
        }
        
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
        
        if (field.equals(TOKEN_ENTRY_FIELDS_ALIAS)) {
            field = TOKEN_ENTRY_FIELDS_KEY_ALIAS;
        }
        
        if (!noArgOps.contains(op)) {
            if (parts.length < 3) {
                throw new IllegalArgumentException("Missing value");
            }
            
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
                value = parts[2];
            }
        }
        
        return new Term(op, field, value);
    }

    /**
     * Tie together the list of Elem:s to a tree of AND operations.
     * This uses a recursive implementation not expected to work for larger 
     * lists of Elem:s, however as the number of columns are limited it is not 
     * expected to be a real problem.
     * 
     * @param elements
     * @param index Recursive index
     * @return Tree of and-criteria elements
     */
    public static Elem andAll(final List<Elem> elements, final int index) {
        if (index >= elements.size() - 1) {
            return elements.get(index);
        } else {
            return Criteria.and(elements.get(index), andAll(elements, index + 1));
        }
    }

    /**
     * Convert to the CESeCore model Elem:s.
     */
    public static List<Elem> toElements(final List<QueryCondition> conditions) {
        final LinkedList<Elem> results = new LinkedList<>();
        
        if (conditions != null) {
            for (QueryCondition cond : conditions) {
                final Object value;
                if (LONG_COLUMNS.contains(cond.getColumn())) {
                    value = Long.parseLong(cond.getValue());
                } else if (INT_COLUMNS.contains(cond.getColumn())) {
                    value = Integer.parseInt(cond.getValue());
                } else if (cond.getColumn().equals(TOKEN_ENTRY_FIELDS_ALIAS)) {
                    cond.setColumn(TOKEN_ENTRY_FIELDS_KEY_ALIAS);
                    value = cond.getValue();
                } else {
                    value = cond.getValue();
                }
                results.add(new Term(cond.getOperator(), cond.getColumn(), value));
            }
        }

        return results;
    }
    
}
