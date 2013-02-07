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

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.signserver.admin.gui.adminws.gen.LogEntry;
import org.signserver.admin.gui.adminws.gen.LogEntry.AdditionalDetails;
import org.signserver.admin.gui.adminws.gen.LogEntry.AdditionalDetails.Entry;

/**
 * Table Model for the audit log.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class AuditlogTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = new String [] {
                "Time", "Outcome", "Event", "Module", "Admin Subject", "Admin Serial Number", "Admin Issuer", "Worker ID", "Node", "Details"
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
            case 1: result = entries.get(rowIndex).getEventStatus(); break;
            case 2: result = entries.get(rowIndex).getEventType(); break;
            case 3: result = entries.get(rowIndex).getModuleType(); break;
            case 4: result = entries.get(rowIndex).getAuthToken(); break;
            case 5: result = entries.get(rowIndex).getSearchDetail1(); break;
            case 6: result = entries.get(rowIndex).getCustomId(); break;
            case 7: result = entries.get(rowIndex).getSearchDetail2(); break;
            case 8: result = entries.get(rowIndex).getNodeId(); break;
            case 9: result = toFirstLineString(entries.get(rowIndex).getAdditionalDetails()); break;
            default: result = "";
        }
        return result;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }
    
    /**
     * Sets the new entries and updates the table.
     * @param entries the new log entries to set
     */
    public void setEntries(List<LogEntry> entries) {
        this.entries = entries;
        fireTableDataChanged();
    }

    /**
     * @param sel the row index to get the log entry for
     * @return the log entry object of the requested row or null
     */
    public LogEntry getRow(int sel) {
        return entries.get(sel);
    }

    private String toFirstLineString(AdditionalDetails details) {
        final StringBuilder buff = new StringBuilder();
        final Iterator<Entry> it = details.getEntry().iterator();
        if (it.hasNext()) {
            final Entry entry = it.next();
            buff.append(entry.getKey()).append("=").append(entry.getValue());
            if (it.hasNext()) {
                buff.append("...");
            }
        }
        return buff.toString();
    }
}
