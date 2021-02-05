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

import java.awt.Component;
import javax.swing.JCheckBox;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Cell renderer rendering the cell as a boolean value in presented
 * as a check mark.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public class CheckboxCellRenderer extends DefaultTableCellRenderer {

    private JCheckBox checkBox = new JCheckBox();
    
    @Override
    public Component getTableCellRendererComponent(final JTable table,
                                                   final Object value,
                                                   final boolean isSelected,
                                                   final boolean hasFocus,
                                                   final int row,
                                                   final int column) {
        final boolean isSet = (Boolean) value;
        
        checkBox.setSelected(isSet);
        
        return checkBox;
    }
    
}
