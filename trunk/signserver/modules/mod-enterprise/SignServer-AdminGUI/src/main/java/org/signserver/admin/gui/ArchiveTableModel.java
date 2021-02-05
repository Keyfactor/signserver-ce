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
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.apache.commons.lang.time.FastDateFormat;

import org.signserver.admin.gui.adminws.gen.ArchiveEntry;
import org.signserver.common.ArchiveMetadata;

/**
 * Table model for archive search result.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ArchiveTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = new String [] {
                "Archive ID", "Time", "Type", "Signer ID", "Client Cert Serial Number", "Issuer DN", "IP Address"
            };
    
    private final FastDateFormat fdf = FastDateFormat.getInstance("yyyy-MM-dd HH:mm:ssZ");
    
    
    private List<ArchiveEntry> entries = Collections.emptyList();
    
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
        final ArchiveEntry entry = entries.get(rowIndex);
        
        switch(columnIndex) {
            case 0:
                result = entry.getArchiveId();
                break;
            case 1:
                result = fdf.format(entry.getTime());
                break;
            case 2:
                result = ArchiveMetadata.getTypeName(entry.getType());
                break;
            case 3:
                result = entry.getSignerId();
                break;
            case 4:
                result = entry.getRequestCertSerialNumber();
                break;
            case 5:
                result = entry.getRequestIssuerDN();
                break;
            case 6:
                result = entry.getRequestIP();
                break;
            default:
                result = "";
        }
        
        return result;
    }
    
    @Override
    public String getColumnName(final int columnIndex) {
        return COLUMNS[columnIndex];
    }

    /**
     * Set archive meta data entries in the table model.
     * 
     * @param entries 
     */
    void setEntries(final List<ArchiveEntry> entries) {
        this.entries = entries;
        fireTableDataChanged();
    }
    
    /**
     * Get archive meta data entries from the table model.
     * 
     * @return List of meta data
     */
    List<ArchiveEntry> getEntries() {
        return entries;
    }
    
}
