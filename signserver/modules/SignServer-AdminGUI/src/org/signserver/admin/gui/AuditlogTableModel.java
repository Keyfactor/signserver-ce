/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.admin.gui;

import java.util.Collections;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.signserver.admin.gui.adminws.gen.LogEntry;

/**
 *
 * @author markus
 */
public class AuditlogTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = new String [] {
                "Time", "Event", "Outcome", "Administrator", "Module", "Certificate Authority", "Certificate", "Username", "Node", "Details"
            };
    
    private List<LogEntry> entries = Collections.emptyList();
    
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
            case 0: result = entries.get(rowIndex).getTimeStamp(); break;
            case 1: result = entries.get(rowIndex).getEventType(); break;
            case 2: result = entries.get(rowIndex).getEventStatus(); break;
            case 3: result = entries.get(rowIndex).getAuthToken(); break;
            case 4: result = entries.get(rowIndex).getModuleType(); break;
            case 5: result = entries.get(rowIndex).getCustomId(); break;
            case 6: result = entries.get(rowIndex).getSearchDetail1(); break;
            case 7: result = entries.get(rowIndex).getSearchDetail2(); break;
            case 8: result = entries.get(rowIndex).getNodeId(); break;
            case 9: result = entries.get(rowIndex).getAdditionalDetails().toString(); break;
            default: result = "";
        }
        return result;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }
    
    
    
    public void setEntries(List<LogEntry> entries) {
        this.entries = entries;
        fireTableDataChanged();
    }

    public LogEntry getRow(int sel) {
        return entries.get(sel);
    }
}
