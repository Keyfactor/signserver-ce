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
import java.util.ArrayList;
import java.util.List;
import javax.swing.DefaultCellEditor;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JTable;
import javax.swing.table.TableCellEditor;

/**
 * Custom cell editor implementing a combo box with pre-defined entries
 * for the standard hard-coded aliases (DEFAULTKEY and NEXTKEY)
 * as well as with the possibility of entering a token entry alias manually.
 *
 * @author Marcus Lundblad
 * @version $Id$
 */
public class AliasCellEditor extends DefaultCellEditor
        implements TableCellEditor {
    private final List<JComboBox> comboBoxes =
            new ArrayList<JComboBox>();
    private Object value;
    private final List<Worker> workers;
    private JComboBox comboBox;
    private boolean alwaysEditable;
    
    public AliasCellEditor(final List<Worker> workers,
                           final JComboBox comboBox,
                           final boolean alwaysEditable) {
        super(comboBox);
        this.comboBox = comboBox;
        this.workers = workers;
        this.alwaysEditable = alwaysEditable;
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
            
            if (!alwaysEditable) {
                final Object editableValue = table.getValueAt(row, 4);
                final boolean editable = editableValue instanceof Boolean && (Boolean) editableValue;
                comboBox.setEditable(editable);
            } else {
                comboBox.setEditable(true);
            }

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
