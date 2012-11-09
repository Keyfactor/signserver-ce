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
import java.awt.Frame;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Vector;
import javax.ejb.EJBException;
import javax.swing.DefaultCellEditor;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import org.apache.log4j.Logger;
import org.jdesktop.application.Action;
import org.jdesktop.application.Task;
import org.signserver.admin.gui.adminws.gen
        .AdminNotAuthorizedException_Exception;
import org.signserver.admin.gui.adminws.gen
        .CryptoTokenOfflineException_Exception;
import org.signserver.admin.gui.adminws.gen.InvalidWorkerIdException_Exception;
import org.signserver.admin.gui.adminws.gen.KeyStoreException_Exception;
import org.signserver.admin.gui.adminws.gen.KeyTestResult;

/**
 * Dialog for testing keys.
 * @author Markus Kilås
 * @version $Id$
 */
@SuppressWarnings("PMD.UnusedFormalParameter")
public class TestKeysDialog extends JDialog {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(TestKeysDialog.class);

    public static final int CANCEL = 0;
    public static final int OK = 1;

    private static final Vector<String> COLUMN_NAMES = new Vector<String>(Arrays.asList(
            new String[] {
        "Signer", "Key alias"
    }));

    private int resultCode = CANCEL;

    private Vector<Vector<String>> data;
    
    private JComboBox aliasComboBox = new JComboBox(new String[] {
        "all"
    });

    private List<Worker> workers;

    /** Creates new form GenerateRequestsDialog */
    public TestKeysDialog(final Frame parent, final boolean modal,
            final List<Worker> workers) {
        super(parent, modal);
        this.workers = new ArrayList<Worker>(workers);
        aliasComboBox.setEditable(true);
        initComponents();
        setTitle("Test keys for " + workers.size() + " signers");

        data = new Vector<Vector<String>>();
        for (Worker worker : workers) {
            Vector<String> cols = new Vector<String>();
            cols.add(worker.getName() + " (" + worker.getWorkerId() + ")");
            String alias
                    = worker.getConfiguration().getProperty("NEXTCERTSIGNKEY");
            if (alias == null) {
                alias = worker.getConfiguration().getProperty("DEFAULTKEY");
            }
            if (alias == null) {
                alias = "all";
            }
            cols.add(alias);
            data.add(cols);
        }
        jTable1.setModel(new DefaultTableModel(data, COLUMN_NAMES) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return column > 0;
            }

            @Override
            public void setValueAt(Object aValue, int row, int column) {
                data.get(row).set(column, (String) aValue);
                super.setValueAt(aValue, row, column);
            }

        });
         jTable1.getModel().addTableModelListener(new TableModelListener() {

            @Override
            public void tableChanged(final TableModelEvent e) {
                tableChangedPerformed(e);
            }
        });

        final BrowseCellEditor editor = new BrowseCellEditor(new JTextField(),
                JFileChooser.SAVE_DIALOG);
        editor.setClickCountToStart(1);
        final DefaultCellEditor textFieldEditor
                = new DefaultCellEditor(new JTextField());
        final DefaultCellEditor comboBoxFieldEditor
                = new DefaultCellEditor(aliasComboBox) {

            @Override
            public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {

                Worker worker = workers.get(row);
                Vector<String> keys = new Vector<String>();
                if (worker.getConfiguration().getProperty("NEXTCERTSIGNKEY")
                        != null) {
                    keys.add(worker.getConfiguration().getProperty("NEXTCERTSIGNKEY"));
                }
                if (worker.getConfiguration().getProperty("DEFAULTKEY")
                        != null) {
                    keys.add(worker.getConfiguration().getProperty("DEFAULTKEY"));
                }
                keys.add("all");
                aliasComboBox.setModel(new DefaultComboBoxModel(keys));

                return super.getTableCellEditorComponent(table, value, isSelected, row, column);
            }

        };
        comboBoxFieldEditor.setClickCountToStart(1);
        textFieldEditor.setClickCountToStart(1);

        jTable1.getColumnModel().getColumn(1)
                .setCellEditor(comboBoxFieldEditor);
        tableChangedPerformed(null);
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

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(TestKeysDialog.class);
        passwordPanelLabel.setText(resourceMap.getString("passwordPanelLabel.text")); // NOI18N
        passwordPanelLabel.setName("passwordPanelLabel"); // NOI18N

        passwordPanelField.setText(resourceMap.getString("passwordPanelField.text")); // NOI18N
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

        jButton2.setText(resourceMap.getString("jButton2.text")); // NOI18N
        jButton2.setName("jButton2"); // NOI18N
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getActionMap(TestKeysDialog.class, this);
        jButtonGenerate.setAction(actionMap.get("keyTesting")); // NOI18N
        jButtonGenerate.setText(resourceMap.getString("jButtonGenerate.text")); // NOI18N
        jButtonGenerate.setName("jButtonGenerate"); // NOI18N

        jScrollPane1.setName("jScrollPane1"); // NOI18N

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null, null},
                {null, null, null, null, null},
                {null, null, null, null, null},
                {null, null, null, null, null},
                {null, null, null, null, null},
                {null, null, null, null, null}
            },
            new String [] {
                "Signer", "Old key alias", "Key algorithm", "Key specification", "New key alias"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Object.class, java.lang.Object.class, java.lang.String.class, java.lang.Object.class, java.lang.Object.class
            };
            boolean[] canEdit = new boolean [] {
                false, false, true, true, true
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        jTable1.setName("jTable1"); // NOI18N
        jScrollPane1.setViewportView(jTable1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 855, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jButton2)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButtonGenerate)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 308, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButtonGenerate)
                    .addComponent(jButton2))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void tableChangedPerformed(final TableModelEvent e) {
        boolean enable = true;
        for (int row = 0; row < jTable1.getRowCount(); row++) {
            if ("".equals(jTable1.getValueAt(row, 1))) {
                enable = false;
                break;
            }
        }
        jButtonGenerate.setEnabled(enable);
    }

    public Vector<Vector<String>> getData() {
        return data;
    }

    public int getResultCode() {
        return resultCode;
    }

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        dispose();
}//GEN-LAST:event_jButton2ActionPerformed

    public int showRequestsDialog() {
        setVisible(true);
        return resultCode;
    }

    @Action(block = Task.BlockingScope.WINDOW)
    public Task keyTesting() {
        return new KeyTestingTask(org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class));
    }

    private class KeyTestingTask extends Task<String, Void> {

        private char[] authCode;

        KeyTestingTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to KeyTestingTask fields, here.
            super(app);
            resultCode = OK;

            passwordPanelLabel.setText(
                "Enter authentication code for all workers or leave empty:");
            passwordPanelField.setText("");
            passwordPanelField.grabFocus();

            int res = JOptionPane.showConfirmDialog(TestKeysDialog.this,
                    passwordPanel, "Test keys",
                    JOptionPane.OK_CANCEL_OPTION);

           if (res == JOptionPane.OK_OPTION) {
               authCode = passwordPanelField.getPassword();
           }
        }
        @Override protected String doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            int numWorkers = data.size();
            int progress = 0;
            setProgress(progress++, 0, numWorkers);
            String results = null;
            if (authCode != null) {
                final StringBuilder sb = new StringBuilder();
                try {
                   for (int row = 0; row < data.size(); row++) {
                        final Worker worker = workers.get(row);
                        final int signerId = worker.getWorkerId();
                        final String alias = data.get(row).get(1);

                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Testing keys: worker=" + signerId
                                    + ", alias: " + alias);
                        }

                        sb.append("Testing keys for signer " + signerId
                                + " with alias " + alias + ":");
                        sb.append("\n");

                        try {
                            // Test the key
                            final Collection<KeyTestResult> result =
                                    SignServerAdminGUIApplication
                                    .getAdminWS()
                                    .testKey(signerId, alias, new String(authCode));

                            if (result.isEmpty()) {
                                sb.append("  ");
                                sb.append("(No key found, token offline?)");
                                sb.append("\n");
                            } else {
                                for (KeyTestResult key : result) {
                                    sb.append("  ");
                                    sb.append(key.getAlias());
                                    sb.append(", ");
                                    sb.append(key.isSuccess()
                                            ? "SUCCESS" : "FAILURE");
                                    sb.append(", ");
                                    sb.append(key.getPublicKeyHash());
                                    sb.append(", ");
                                    sb.append(key.getStatus());
                                    sb.append("\n");
                                }
                            }

                        } catch (AdminNotAuthorizedException_Exception ex) {
                            sb.append(ex.getMessage());
                            sb.append("\n");
                        } catch (CryptoTokenOfflineException_Exception ex) {
                            sb.append(ex.getMessage());
                            sb.append("\n");
                        } catch (InvalidWorkerIdException_Exception ex) {
                            sb.append(ex.getMessage());
                            sb.append("\n");
                        } catch (KeyStoreException_Exception ex) {
                            sb.append(ex.getMessage());
                            sb.append("\n");
                        } catch (EJBException ex) {
                            LOG.error(ex.getMessage(), ex);
                            sb.append(ex.getMessage());
                            sb.append("\n");
                        } catch (RuntimeException ex) {
                            sb.append("Not supported by server: ")
                                    .append(ex.getMessage())
                                    .append("\n");
                        }
                        sb.append("\n");
                        setProgress(progress++, 0, numWorkers);
                    }
                } finally {
                    for (int i = 0; i < authCode.length; i++) {
                        authCode[i] = 0;
                    }
                }
                results = sb.toString();
            }
            return results;  // return your result
        }
        @Override protected void succeeded(final String results) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            if (results != null) {
                JOptionPane.showMessageDialog(TestKeysDialog.this,
                            results);
                dispose();
            }
        }
        
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
