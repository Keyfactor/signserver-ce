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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.table.AbstractTableModel;
import org.signserver.admin.gui.adminws.gen.TokenEntry;

/**
 * Table Model for the crypto token entries.
 *
 * @author Markus Kilås
 * @version $Id: AuditlogTableModel.java 3316 2013-02-09 13:18:09Z netmackan $
 */
public class TokenEntriesTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = new String [] {
            "Alias", "Type", "Certificates"
        };
    
    private static final Map<String, String> typeTitles = new HashMap<String, String>();
    
    static {
        typeTitles.put(org.signserver.server.cryptotokens.TokenEntry.TYPE_PRIVATEKEY_ENTRY, "Asymmetric");
        typeTitles.put(org.signserver.server.cryptotokens.TokenEntry.TYPE_SECRETKEY_ENTRY, "Symmetric");
        typeTitles.put(org.signserver.server.cryptotokens.TokenEntry.TYPE_TRUSTED_ENTRY, "Trusted");
    }

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
        final TokenEntry entry = entries.get(rowIndex);
        switch (columnIndex) {
            case 0: result = entry.getAlias(); break;
            case 1: {
                String title = typeTitles.get(entry.getType());
                if (title == null) {
                    title = entry.getType();
                }
                result = title;
            } break;
            case 2: {
                if (entry.getChain() != null && !entry.getChain().isEmpty()) {
                    result = String.valueOf(entry.getChain().size());
                } else if (entry.getTrustedCertificate() != null && entry.getTrustedCertificate().length > 0) {
                    result = "1";
                } else {
                    result = "0";
                }
                break;
            }
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
