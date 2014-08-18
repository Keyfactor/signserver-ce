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
import java.util.List;
import javax.swing.table.AbstractTableModel;

import org.signserver.admin.gui.adminws.gen.ArchiveEntry;
import org.signserver.common.ArchiveDataVO;
import org.signserver.server.archive.Archivable;

/**
 * Table model for archive search result.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class ArchiveTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = new String [] {
                "Archive ID", "Time", "Type", "Signer ID", "Admin Serial Number", "Admin Issuer", "IP Address"
            };
    
    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");
    
    
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
            case 1:
                result = entry.getArchiveId();
                break;
            case 2:
                result = sdf.format(entry.getTime());
                break;
            case 3:
                final int type = entry.getType();
                result = type == ArchiveDataVO.TYPE_REQUEST ? 
                        Archivable.TYPE_REQUEST : Archivable.TYPE_RESPONSE;
                break;
            case 4:
                result = entry.getSignerId();
                break;
            case 5:
                result = entry.getRequestCertSerialNumber();
                break;
            case 6:
                result = entry.getRequestIssuerDN();
                break;
            case 7:
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
    
}
