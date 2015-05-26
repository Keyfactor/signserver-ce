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
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.signserver.admin.gui.adminws.gen.LogEntry;
import org.signserver.admin.gui.adminws.gen.LogEntry.AdditionalDetails;
import org.signserver.admin.gui.adminws.gen.LogEntry.AdditionalDetails.Entry;
import org.signserver.admin.gui.adminws.gen.TokenEntry;

/**
 * Table Model for the crypto token entries.
 *
 * @author Markus Kilås
 * @version $Id: AuditlogTableModel.java 3316 2013-02-09 13:18:09Z netmackan $
 */
public class TokenEntriesTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = new String [] {
                "Alias", "Type", "Certificates", /*"Creation Date"*/
            };
    
    //private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");
    
    private List<TokenEntry> entries = Collections.emptyList();
    
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
            case 0: result = entries.get(rowIndex).getAlias(); break;
            case 1: result = entries.get(rowIndex).getType(); break;
            case 2: result = entries.get(rowIndex).getChain(); break;
            //case 3: result = entries.get(rowIndex).getCreationDate(); break;
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
    public void setEntries(List<TokenEntry> entries) {
        this.entries = entries;
        fireTableDataChanged();
    }

    /**
     * @param sel the row index to get the log entry for
     * @return the log entry object of the requested row or null
     */
    public TokenEntry getRow(int sel) {
        return entries.get(sel);
    }

}
