/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.signserver.admin.gui;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.AbstractCellEditor;
import javax.swing.DefaultCellEditor;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JTable;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.table.TableCellEditor;

/**
 *
 * @author marcus
 */
public class AliasCellEditor extends DefaultCellEditor
        implements TableCellEditor {
    private final List<JComboBox> comboBoxes =
            new ArrayList<JComboBox>();
    private Object value;
    private final List<Worker> workers;
    private JComboBox comboBox;
    
    public AliasCellEditor(final List<Worker> workers, final JComboBox comboBox) {
        super(comboBox);
        this.comboBox = comboBox;
        this.workers = workers;
    }

    @Override
    public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
        this.value = value;
        this.comboBox = (JComboBox) super.getTableCellEditorComponent(table, value, isSelected, row, column);
        
        if (row >= 0) {
            final Worker worker = workers.get(row);
            final Object nextKeyObject =
                    new Utils.HardCodedAliasValue(Utils.HardCodedAlias.NEXT_KEY,
                                                  worker);
            final Object defaultKeyObject =
                    new Utils.HardCodedAliasValue(Utils.HardCodedAlias.DEFAULT_KEY,
                                                  worker);

            comboBox.setModel(new DefaultComboBoxModel(value instanceof String ?
                                    new Object[] {nextKeyObject, defaultKeyObject, value} :
                                    new Object[] {nextKeyObject, defaultKeyObject}));
            final Object editableValue = table.getValueAt(row, 4);
            final boolean editable = editableValue instanceof Boolean && (Boolean) editableValue;
            comboBox.setEditable(editable);

            if (value instanceof Utils.HardCodedAliasValue) {
                final Utils.HardCodedAlias alias = ((Utils.HardCodedAliasValue) value).getHardCodedAlias();

                if (Utils.HardCodedAlias.NEXT_KEY.equals(alias)) {
                    comboBox.setSelectedIndex(0);
                } else {
                    comboBox.setSelectedIndex(1);
                }
            }
        }

        return comboBox;
    }
}
