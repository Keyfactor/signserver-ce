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

import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * DocumentListener updating the JTable the associated JTextField is modifying
 * by calling an overridable updating method.
 * 
 * @author Marcus Lundblad
 * @version $Id$
 */
public abstract class TextFieldTableUpdatingDocumentListener 
    implements DocumentListener {
    private final JTextField textField;
    private final JTable table;

    public TextFieldTableUpdatingDocumentListener(final JTextField textField,
                                                  final JTable table) {
        this.textField = textField;
        this.table = table;
    }
    
    /**
     * Called after inserting back updated text values into the table.
     * Implementations of this method should update the corresponding action
     * buttons enabledness.
     */
    protected abstract void tableChangedPerformed();
    
    private void changed() {
        final int col = table.getEditingColumn();
        final int row = table.getEditingRow();
        
        if (col != -1 && row != -1) {
            table.getModel().setValueAt(textField.getText(), row, col);
            tableChangedPerformed();
        }
    }

    @Override
    public void insertUpdate(DocumentEvent e) {
        changed();
    }

    @Override
    public void removeUpdate(DocumentEvent e) {
        changed();
    }

    @Override
    public void changedUpdate(DocumentEvent e) {
        changed();
    }
}
