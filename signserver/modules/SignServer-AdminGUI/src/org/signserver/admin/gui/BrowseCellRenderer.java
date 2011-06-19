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

import java.awt.BorderLayout;
import java.awt.Component;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * TableCellRenderer showing a browse button.
 * 
 * @author Markus Kilås
 * @version $Id$
 */
public class BrowseCellRenderer extends DefaultTableCellRenderer {

    private JPanel viewPanel = new JPanel(new BorderLayout());

    private JButton viewButton = new JButton("...");

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
            boolean isSelected, boolean hasFocus, int row, int column) {

        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        viewPanel = new JPanel(new BorderLayout());
        viewPanel.add(this, BorderLayout.CENTER);
        viewPanel.add(viewButton, BorderLayout.EAST);
        return viewPanel;
    }
}
