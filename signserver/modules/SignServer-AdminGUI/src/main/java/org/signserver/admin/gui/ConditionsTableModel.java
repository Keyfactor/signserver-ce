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

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.signserver.admin.gui.adminws.gen.QueryCondition;
import org.signserver.admin.gui.adminws.gen.RelationalOperator;

/**
 * Table Model for the query conditions.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class ConditionsTableModel extends AbstractTableModel {
    
    private static final String[] COLUMNS = new String [] {
                "Column", "Condition", "Value"
            };
    
    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");
    
    private List<QueryCondition> entries = new ArrayList<QueryCondition>();

    @Override
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Object result;
        final QueryCondition row = entries.get(rowIndex);
        switch (columnIndex) {
            case 0: result = AuditlogColumn.getDescription(row.getColumn()) + " (" + entries.get(rowIndex).getColumn() + ")"; break;
            case 1: result = QueryOperator.fromEnum(row.getOperator()); break;
            case 2: {
                result = row.getValue();
                if (AuditRecordData.FIELD_TIMESTAMP.equals(row.getColumn()) && result instanceof String) {
                    try {
                        final long time = Long.parseLong((String) result);
                        result = sdf.format(new Date(time)) + " (" + time + ")";
                    } catch (NumberFormatException ignored) {}
                }
            } break;
            default: result = "";
        }
        return result;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }
    
    /**
     * Add a condition to the table and inform all listeners about the update.
     * @param column Name of the column
     * @param operator The relational operator
     * @param value The value
     */
    public void addCondition(String column, RelationalOperator operator, String value) {
        QueryCondition qc = new QueryCondition();
        qc.setColumn(column);
        qc.setOperator(operator);
        qc.setValue(value);
        entries.add(qc);
        fireTableRowsInserted(entries.size() - 1, entries.size() - 1);
    }
    
    /**
     * Remove a condition from the table.
     * @param row Index of the row to remove
     */
    public void removeCondition(int row) {
        entries.remove(row);
        fireTableRowsDeleted(row, row);
    }

    /**
     * @return A view of the table content
     */
    public List<QueryCondition> getEntries() {
        return Collections.unmodifiableList(entries);
    }
    
}
