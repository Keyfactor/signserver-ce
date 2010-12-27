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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;
import javax.ejb.EJBException;
import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import org.apache.log4j.Logger;
import org.jdesktop.application.Action;
import org.jdesktop.application.Application;
import org.jdesktop.application.Task;
import org.signserver.admin.gui.adminws.gen
        .AdminNotAuthorizedException_Exception;

/**
 * Dialog for renewing keys.
 * @author Markus Kilås
 * @version $Id$
 */
public class RenewKeysDialog extends JDialog {

    /** Logger for this class. */
    private static final Logger LOG
            = Logger.getLogger(RenewKeysDialog.class);

    public static final int CANCEL = 0;
    public static final int OK = 1;

    private static final Vector<String> COLUMN_NAMES = new Vector(Arrays.asList(
            new String[] {
        "Signer", "Old key alias", "Key algorithm", "Key specification",
        "New key alias"
    }));

    private int resultCode = CANCEL;

    private Vector<Vector<String>> data;
    
    private JComboBox keyAlgComboBox = new JComboBox(new String[] {
        "RSA",
        "DSA",
        "ECDSA"
    });

    private List<Worker> workers;

    /** Creates new form GenerateRequestsDialog */
    public RenewKeysDialog(final Frame parent, final boolean modal,
            final List<Worker> workers) {
        super(parent, modal);
        this.workers = new ArrayList<Worker>(workers);
        keyAlgComboBox.setEditable(true);
        initComponents();
        setTitle("Renew keys for " + workers.size() + " signers");

        data = new Vector<Vector<String>>();
        for (Worker worker : workers) {
            Vector<String> cols = new Vector<String>();
            cols.add(worker.getName() + " (" + worker.getWorkerId() + ")");
            final String oldAlias
                    = worker.getConfiguration().getProperty("DEFAULTKEY");
            cols.add(oldAlias);
            cols.add(worker.getConfiguration().getProperty("KEYALG"));
            cols.add(worker.getConfiguration().getProperty("KEYSPEC"));
            if (oldAlias == null || oldAlias.isEmpty()) {
                cols.add("");
            } else {
                cols.add(nextAliasInSequence(oldAlias));
            }
            data.add(cols);
        }
        jTable1.setModel(new DefaultTableModel(data, COLUMN_NAMES) {

            @Override
            public boolean isCellEditable(int row, int column) {
                return column > 1;
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
                boolean enable = true;
                for (int row = 0; row < jTable1.getRowCount(); row++) {
                    if ("".equals(jTable1.getValueAt(row, 2))
                            || "".equals(jTable1.getValueAt(row, 3))
                            || "".equals(jTable1.getValueAt(row, 4))) {
                        enable = false;
                        break;
                    }
                }
                jButtonGenerate.setEnabled(enable);
            }
        });

        final BrowseCellEditor editor = new BrowseCellEditor(new JTextField(),
                JFileChooser.SAVE_DIALOG);
        editor.setClickCountToStart(1);
        final DefaultCellEditor textFieldEditor
                = new DefaultCellEditor(new JTextField());
        final DefaultCellEditor comboBoxFieldEditor
                = new DefaultCellEditor(keyAlgComboBox);
        comboBoxFieldEditor.setClickCountToStart(1);
        textFieldEditor.setClickCountToStart(1);

        jTable1.getColumnModel().getColumn(2)
                .setCellEditor(comboBoxFieldEditor);
        jTable1.getColumnModel().getColumn(3)
                .setCellEditor(textFieldEditor);
        jTable1.getColumnModel().getColumn(4)
                .setCellEditor(textFieldEditor);
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

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(RenewKeysDialog.class);
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

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getActionMap(RenewKeysDialog.class, this);
        jButtonGenerate.setAction(actionMap.get("renewKeys")); // NOI18N
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

    public Vector<Vector<String>> getData() {
        return data;
    }

    public int getResultCode() {
        return resultCode;
    }

    static String nextAliasInSequence(final String currentAlias) {
        String prefix = currentAlias;
        String nextSequence = "2";

        final String[] entry = currentAlias.split("[0-9]+$");
        if (entry.length == 1) {
            prefix = entry[0];
            final String currentSequence
                    = currentAlias.substring(prefix.length());
            final int sequenceChars = currentSequence.length();
            if (sequenceChars > 0) {
                final long nextSequenceNumber = Long.parseLong(currentSequence) + 1;
                final String nextSequenceNumberString
                        = String.valueOf(nextSequenceNumber);
                if (sequenceChars > nextSequenceNumberString.length()) {
                    nextSequence = currentSequence.substring(0,
                            sequenceChars - nextSequenceNumberString.length())
                            + nextSequenceNumberString;
                } else {
                    nextSequence = nextSequenceNumberString;
                }
            }
        }

        return prefix + nextSequence;
    }

//    public void checkThatWorkerIsProcessable(int signerid, String hostname) {
//    	Collection<Integer> signerIds
//                = SignServerAdminGUIApplication.getWorkerSession().getWorkers(
//                GlobalConfiguration.WORKERTYPE_PROCESSABLE);
//    	if(!signerIds.contains(new Integer(signerid))){
//    		throw new IllegalAdminCommandException("Error: given workerId doesn't seem to point to any processable worker in the system.");
//    	}
//
//    }

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        dispose();
}//GEN-LAST:event_jButton2ActionPerformed

    public int showRequestsDialog() {
        setVisible(true);
        return resultCode;
    }

    @Action(block = Task.BlockingScope.WINDOW)
    public Task renewKeys() {
        return new RenewKeysTask(org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class));
    }

    private class RenewKeysTask extends Task<String, Void> {

        private char[] authCode;

        RenewKeysTask(final Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to RenewKeysTask fields, here.
            super(app);
            resultCode = OK;
            final String hostname = null;

            passwordPanelLabel.setText(
                    "Enter authentication code for all workers or leave empty:");
            passwordPanelField.setText("");
            passwordPanelField.grabFocus();

            int res = JOptionPane.showConfirmDialog(RenewKeysDialog.this,
                    passwordPanel, "Generate keys",
                    JOptionPane.OK_CANCEL_OPTION);

           if (res == JOptionPane.OK_OPTION) {
               authCode = passwordPanelField.getPassword();
           }
        }
        @Override protected String doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            final int numWorkers = data.size();
            String errors = null;
            if (authCode != null) {
                final StringBuilder sb = new StringBuilder();
                try {
                   int progress = 0;
                   setProgress(progress++, 0, numWorkers);
                   for (int row = 0; row < data.size(); row++) {
                        final Worker worker = workers.get(row);
                        final int signerId = worker.getWorkerId();
                        final String keyAlg =  (String) data.get(row).get(2);
                        final String keySpec = (String) data.get(row).get(3);
                        final String alias = (String) data.get(row).get(4);

                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Key generation: worker=" + signerId
                                    + ", keyAlg=" + keyAlg + ", keySpec="
                                    + keySpec + ", alias: " + alias);
                        }

                        String newAlias = null;
                        try {
                            // Generate key
                            newAlias = SignServerAdminGUIApplication
                                .getAdminWS().generateSignerKey(signerId,
                                keyAlg, keySpec, alias, new String(authCode));

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
                            try {
                                LOG.debug("Created key " + newAlias + " for signer "
                                        + signerId);

                                // Update key label
                                SignServerAdminGUIApplication.getAdminWS()
                                        .setWorkerProperty(signerId,
                                        "NEXTCERTSIGNKEY", newAlias);

                                // Reload configuration
                                SignServerAdminGUIApplication.getAdminWS()
                                        .reloadConfiguration(signerId);

                                LOG.debug("Configured new key " + newAlias
                                        + " for signer " + signerId);

                                workers.remove(worker);
                                data.remove(row);
                                row--;
                            } catch (AdminNotAuthorizedException_Exception e) {
                                final String error =
                                        "Error generating key for signer "
                                        + signerId + ":\n" + e
                                        .getMessage();
                                LOG.error(error, e);
                                sb.append(error);
                                sb.append("\n");
                            }
                        }
                        setProgress(progress++, 0, numWorkers);
                    }
                   errors = sb.toString();
               } finally {
                    for (int i = 0; i < authCode.length; i++) {
                        authCode[i] = 0;
                    }
               }
            }
            return errors;  // return your result
        }
        @Override protected void succeeded(final String result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().
            if (result != null) {
                if (result.length() > 0) {
                    jTable1.revalidate();
                    JOptionPane.showMessageDialog(RenewKeysDialog.this,
                                            result, "Key renewal error",
                                            JOptionPane.ERROR_MESSAGE);
                }
                if (data.size() == 0) {
                    JOptionPane.showMessageDialog(RenewKeysDialog.this,
                            "Renewed keys for all choosen signers.");
                    dispose();
                }
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
