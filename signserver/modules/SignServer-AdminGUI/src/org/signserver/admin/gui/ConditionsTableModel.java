/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.admin.gui;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.signserver.admin.gui.adminws.gen.QueryCondition;
import org.signserver.admin.gui.adminws.gen.RelationalOperator;

/**
 *
 * @author markus
 */
public class ConditionsTableModel extends AbstractTableModel {
    
    private static final String[] COLUMNS = new String [] {
                "Column", "Condition", "Value"
            };
    
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
        final Object result;
        switch (columnIndex) {
            case 0: result = AuditlogColumn.getDescription(entries.get(rowIndex).getColumn()) + " (" + entries.get(rowIndex).getColumn() + ")"; break;
            case 1: result = AuditlogOperator.fromEnum(entries.get(rowIndex).getOperator()); break;
            case 2: result = entries.get(rowIndex).getValue(); break;
            default: result = "";
        }
        return result;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }
    
    public void addCondition(String column, RelationalOperator operator, String value) {
        QueryCondition qc = new QueryCondition();
        qc.setColumn(column);
        qc.setOperator(operator);
        qc.setValue(value);
        entries.add(qc);
        fireTableRowsInserted(entries.size() - 1, entries.size() - 1);
    }
    
    public void removeCondition(int column) {
        entries.remove(column);
        fireTableRowsDeleted(column, column);
    }

    public List<QueryCondition> getEntries() {
        return Collections.unmodifiableList(entries);
    }
    
}
