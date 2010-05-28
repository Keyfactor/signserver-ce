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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTextField;

/**
 * Cell editor with text field and button for browsing to a filename to save as.
 *
 * @author markus
 * @version $Id$
 */
class BrowseCellEditor extends DefaultCellEditor implements ActionListener {

    private JButton customEditorButton = new JButton("...");
    private JTable table;
    private int row;
    private int column;
    private JFileChooser chooser = new JFileChooser();

    public BrowseCellEditor(JTextField textField) {
        super(textField);
        customEditorButton.addActionListener(this);
    }

    public void actionPerformed(ActionEvent e) {
        stopCellEditing();
        File currentFile = new File((String) table.getValueAt(row, column));
        chooser.setMultiSelectionEnabled(false);
        chooser.setDialogType(JFileChooser.SAVE_DIALOG);
        chooser.setSelectedFile(currentFile);
        chooser.showOpenDialog(null);
        if (chooser.getSelectedFile() != null) {
            table.setValueAt(chooser.getSelectedFile().getAbsolutePath(), row, column);
        }
    }

    @Override
    public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(super.getTableCellEditorComponent(table, value, isSelected, row, column));
        panel.add(customEditorButton, BorderLayout.EAST);
        this.table = table;
        this.row = row;
        this.column = column;
        return panel;
    }
}
