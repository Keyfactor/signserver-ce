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
import javax.swing.DefaultListCellRenderer;
import javax.swing.Icon;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.border.EmptyBorder;

/**
 * Renders cells with worker name and a small icon. Typically used in combo
 * boxes.
 *
 * @author Markus Kilås
 * @version $Id$
 */
public class SmallWorkerListCellRenderer extends DefaultListCellRenderer {

    private Icon workerIcon;

    public SmallWorkerListCellRenderer(Icon workerIcon) {
        this.workerIcon = workerIcon;
    }

    @Override
    public Component getListCellRendererComponent(final JList list, Object value,
            final int index, final boolean isSelected, final boolean cellHasFocus) {
        final JLabel component =
                (JLabel) super.getListCellRendererComponent(list, value, index,
                isSelected, cellHasFocus);
        component.setBorder(new EmptyBorder(5, 5, 5, 5));
        if (value instanceof Worker) {
            final Worker signer = (Worker) value;
            component.setText(signer.getName() + " (" + signer.getWorkerId() + ")");
            component.setIcon(workerIcon);
        } else {
            component.setIcon(null);
        }
        return component;
    }
}
