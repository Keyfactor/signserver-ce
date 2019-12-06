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

import java.awt.Frame;
import java.util.Arrays;
import java.util.Vector;
import javax.ejb.EJBException;
import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import org.apache.log4j.Logger;
import org.jdesktop.application.Action;
import org.jdesktop.application.Application;
import org.jdesktop.application.Task;

/**
 * Dialog for generating keys in a token.
 *
 * @author Markus Kilås
 * @version $Id$
 * @see RenewKeysDialog
 */
@SuppressWarnings("PMD.UnusedFormalParameter")
public class GenerateKeysDialog extends JDialog {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(GenerateKeysDialog.class);

    public static final int CANCEL = 0;
    public static final int OK = 1;

    private static final Vector<String> COLUMN_NAMES = new Vector<>(Arrays.asList(
            new String[] {
        "New key alias", "Key algorithm", "Key specification"
    }));

    private int resultCode = CANCEL;

    private Vector<Vector<String>> data;
    
    private JComboBox keyAlgComboBox = new JComboBox(new String[] {
        "RSA",
        "DSA",
        "ECDSA"
    });

    private final Worker worker;
    private boolean generateCalled;
    private final DefaultTableModel tableModel;
    
    private final DefaultCellEditor textFieldEditor;

    /** Creates new form GenerateRequestsDialog */
    public GenerateKeysDialog(final Frame parent, final boolean modal,
            final Worker worker) {
        super(parent, modal);
        this.worker = worker;
        keyAlgComboBox.setEditable(true);
        initComponents();
        setTitle("Generate new key(s) in token " + worker.getName());

        data = new Vector<>();
        data.add(createRow());
        tableModel = new DefaultTableModel(data, COLUMN_NAMES) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return true;
            }

            @Override
            public void setValueAt(Object aValue, int row, int column) {
                data.get(row).set(column, (String) aValue);
                super.setValueAt(aValue, row, column);
            }

        };
        jTable1.setModel(tableModel);
         jTable1.getModel().addTableModelListener(new TableModelListener() {

            @Override
            public void tableChanged(final TableModelEvent e) {
                tableChangedPerformed();
            }
        });
        tableChangedPerformed();

        final JTextField textField = new JTextField();
        
        // update button state based on the text field content as editing is
        // in progress, this avoids the problem where you have to click outside
        // the last edited field to "force" a refresh of the "Generate" button
        textField.getDocument().addDocumentListener(
                new TextFieldTableUpdatingDocumentListener(textField, jTable1) {
            @Override
            protected void tableChangedPerformed() {
                GenerateKeysDialog.this.tableChangedPerformed();
            }      
        });

        textFieldEditor = new DefaultCellEditor(textField);
        final DefaultCellEditor comboBoxFieldEditor
                = new DefaultCellEditor(keyAlgComboBox);
        comboBoxFieldEditor.setClickCountToStart(1);
        textFieldEditor.setClickCountToStart(1);

        jTable1.getColumnModel().getColumn(0)
                .setCellEditor(textFieldEditor);
        jTable1.getColumnModel().getColumn(1)
                .setCellEditor(comboBoxFieldEditor);
        jTable1.getColumnModel().getColumn(2)
                .setCellEditor(textFieldEditor);

        jTable1.setRowHeight(keyAlgComboBox.getPreferredSize().height);

        getRootPane().setDefaultButton(jButtonGenerate);
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        passwordPanel = new javax.swing.JPanel();
        passwordPanelLabel = new javax.swing.JLabel();
        passwordPanelField = new javax.swing.JPasswordField();
        jButton2 = new javax.swing.JButton();
        jButtonGenerate = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();

        passwordPanel.setName("passwordPanel"); // NOI18N

        passwordPanelLabel.setName("passwordPanelLabel"); // NOI18N

        passwordPanelField.setName("passwordPanelField"); // NOI18N

        javax.swing.GroupLayout passwordPanelLayout = new javax.swing.GroupLayout(passwordPanel);
        passwordPanel.setLayout(passwordPanelLayout);
        passwordPanelLayout.setHorizontalGroup(
            passwordPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, passwordPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(passwordPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(passwordPanelField, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 391, Short.MAX_VALUE)
                    .addComponent(passwordPanelLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 391, Short.MAX_VALUE))
                .addContainerGap())
        );
        passwordPanelLayout.setVerticalGroup(
            passwordPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(passwordPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(passwordPanelLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(passwordPanelField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setLocationByPlatform(true);
        setName("Form"); // NOI18N

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(GenerateKeysDialog.class);
        jButton2.setText(resourceMap.getString("jButton2.text")); // NOI18N
        jButton2.setName("jButton2"); // NOI18N
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getActionMap(GenerateKeysDialog.class, this);
        jButtonGenerate.setAction(actionMap.get("renewKeys")); // NOI18N
        jButtonGenerate.setText(resourceMap.getString("jButtonGenerate.text")); // NOI18N
        jButtonGenerate.setName("jButtonGenerate"); // NOI18N

        jScrollPane1.setName("jScrollPane1"); // NOI18N

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null},
                {null, null, null},
                {null, null, null},
                {null, null, null},
                {null, null, null},
                {null, null, null}
            },
            new String [] {
                "New key alias", "Key algorithm", "Key specification"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Object.class, java.lang.String.class, java.lang.Object.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        jTable1.setColumnSelectionAllowed(true);
        jTable1.setName("jTable1"); // NOI18N
        jScrollPane1.setViewportView(jTable1);
        jTable1.getColumnModel().getSelectionModel().setSelectionMode(javax.swing.ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        jTable1.getColumnModel().getColumn(0).setHeaderValue(resourceMap.getString("jTable1.columnModel.title4")); // NOI18N
        jTable1.getColumnModel().getColumn(1).setHeaderValue(resourceMap.getString("jTable1.columnModel.title2")); // NOI18N
        jTable1.getColumnModel().getColumn(2).setHeaderValue(resourceMap.getString("jTable1.columnModel.title3")); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 855, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jButton2, javax.swing.GroupLayout.PREFERRED_SIZE, 88, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButtonGenerate)))
                .addContainerGap())
        );

        layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {jButton2, jButtonGenerate});

        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 303, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButtonGenerate)
                    .addComponent(jButton2, javax.swing.GroupLayout.PREFERRED_SIZE, 36, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {jButton2, jButtonGenerate});

        pack();
    }// </editor-fold>//GEN-END:initComponents

    public Vector<Vector<String>> getData() {
        return data;
    }

    public int getResultCode() {
        return resultCode;
    }

    /** Enable/disable the submit button based on the table state. */
    private void tableChangedPerformed() {
        
        // Create a new row if the last is filled in
        if (jTable1.getRowCount() > 0) {
            final int last = jTable1.getRowCount() - 1;
            if (!((String) jTable1.getValueAt(last, 0)).isEmpty()) {
                tableModel.addRow(createRow());
            }
        }
        
        // Clean out any empty rows in the middle
        for (int i = jTable1.getRowCount() - 2; i >= 0; i--) {
            if (((String) jTable1.getValueAt(i, 0)).isEmpty()) {
                tableModel.removeRow(i);
            }
        }
        
        // Enable/disable the OK button
        boolean enable = !"".equals(jTable1.getValueAt(0, 0)); // First row must not be empty

        // Check that all rows except the last one are filled in
        if (enable) {
            for (int row = jTable1.getRowCount() - 2; row >= 0; row--) {
                Object value0 = jTable1.getValueAt(row, 0);
                Object value1 = jTable1.getValueAt(row, 1);
                Object value2 = jTable1.getValueAt(row, 2);
                
                if (value0 == null
                        || value0.equals("")
                        || value1 == null
                        || value1.equals("")
                        || value2 == null
                        || value2.equals("")) {
                    enable = false;
                    break;
                }
            }
        }
        jButtonGenerate.setEnabled(enable);
    }

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        dispose();
}//GEN-LAST:event_jButton2ActionPerformed


    private Vector<String> createRow() {
        Vector<String> cols = new Vector<>();
        cols.add("");
        cols.add(worker.getConfiguration().getProperty("KEYALG"));
        cols.add(worker.getConfiguration().getProperty("KEYSPEC"));
        return cols;
    }

    public int showRequestsDialog() {
        setVisible(true);
        return resultCode;
    }

        @Action(block = Task.BlockingScope.WINDOW)
    public Task renewKeys() {
        return new RenewKeysTask(org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class));
    }

    private class RenewKeysTask extends Task<String, Void> {

        RenewKeysTask(final Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to RenewKeysTask fields, here.
            super(app);
            resultCode = OK;
            generateCalled = true;
            textFieldEditor.stopCellEditing();
        }
        @Override protected String doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            final int numWorkers = data.size();
            final StringBuilder sb = new StringBuilder();
            int progress = 0;
            setProgress(progress++, 0, numWorkers);
            for (int row = 0; row < data.size() - 1; row++) {
                final int signerId = worker.getWorkerId();
                final String alias = (String) data.get(row).get(0);
                final String keyAlg =  (String) data.get(row).get(1);
                final String keySpec = (String) data.get(row).get(2);

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Key generation: worker=" + signerId
                            + ", keyAlg=" + keyAlg + ", keySpec="
                            + keySpec + ", alias: " + alias);
                }

                if (keyAlg == null || keySpec == null || alias == null) {
                    return "Please, fill in all required fields";
                }

                String newAlias = null;
                try {
                    // Generate key
                    newAlias = SignServerAdminGUIApplication
                        .getAdminWS().generateSignerKey(signerId,
                        keyAlg, keySpec, alias, "");

                    if (newAlias == null) {
                        final String error
                                =  "Error generating key for signer "
                                + signerId + ":\n"
                                + "Could not generate key";
                        LOG.error(error);
                        sb.append(error);
                        sb.append("\n");
                    }
                } catch (EJBException eJBException) {
                    if (eJBException.getCausedByException()
                            instanceof IllegalArgumentException) {
                        final String error =
                                "Error generating key for signer "
                                + signerId + ":\n" + eJBException
                                .getCausedByException().getMessage();
                        LOG.error(error, eJBException);
                        sb.append(error);
                        sb.append("\n");
                    } else {
                        final String error =
                                "Error generating key for signer "
                                + signerId + ":\n" + eJBException
                                .getMessage();
                        LOG.error(error, eJBException);
                        sb.append(error);
                        sb.append("\n");
                    }
                } catch (Exception e) {
                    final String error =
                                "Error generating key for signer "
                                + signerId + ":\n" + e
                                .getMessage();
                        LOG.error(error, e);
                        sb.append(error);
                        sb.append("\n");
                }

                if (newAlias != null) {

                    LOG.debug("Created key " + newAlias + " for signer "
                            + signerId);

                    data.remove(row);
                    row--;
                }
                setProgress(progress++, 0, numWorkers);
             }
            return sb.toString();  // return your result
        }
        @Override protected void succeeded(final String result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            if (result != null) {
                if (result.length() > 0) {
                    jTable1.revalidate();
                    JOptionPane.showMessageDialog(GenerateKeysDialog.this,
                                            result, "Key generation error",
                                            JOptionPane.ERROR_MESSAGE);
                }
                if (data.size() == 1) {
                    JOptionPane.showMessageDialog(GenerateKeysDialog.this,
                            "All keys generated.");
                    dispose();
                }
            }
        }
    }

    public boolean isGenerateCalled() {
        return generateCalled;
    }


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButtonGenerate;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable jTable1;
    private javax.swing.JPanel passwordPanel;
    private javax.swing.JPasswordField passwordPanelField;
    private javax.swing.JLabel passwordPanelLabel;
    // End of variables declaration//GEN-END:variables

}
