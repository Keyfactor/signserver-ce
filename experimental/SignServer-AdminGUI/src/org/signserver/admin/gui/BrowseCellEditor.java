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

class BrowseCellEditor extends DefaultCellEditor implements ActionListener {

    JButton customEditorButton = new JButton("...");
    JTable table;
    int row;
    int column;
    JFileChooser chooser = new JFileChooser();

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
