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

import java.awt.event.ActionEvent;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;
import org.jdesktop.application.Action;
import org.jdesktop.application.Task;
import org.signserver.admin.gui.adminws.gen
        .AdminNotAuthorizedException_Exception;
import org.signserver.admin.gui.adminws.gen.WsGlobalConfiguration;
import  org.signserver.common.GlobalConfiguration;

/**
 * Frame for viewing and editing global configuration properties.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@SuppressWarnings("PMD.UnusedFormalParameter")
public class AdministratorsFrame extends javax.swing.JFrame {

    private static final String[] COLUMN_NAMES = new String[] {
        "Certificate serial number",
        "Issuer DN",
        "Admin",
        "Auditor"
    };

    private static final String ALLOWANYWSADMIN = "ALLOWANYWSADMIN";
    
    private List<Entry> entries = Collections.emptyList();

    /** Creates new form GlobalConfigurationFrame */
    public AdministratorsFrame() {
        initComponents();

        adminsTable.setModel(new AbstractTableModel() {

            @Override
            public int getRowCount() {
                return entries.size();
            }

            @Override
            public int getColumnCount() {
                return COLUMN_NAMES.length;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 2 || columnIndex == 3) {
                    return Boolean.class;
                }
                return super.getColumnClass(columnIndex);
            }

            @Override
            public Object getValueAt(int rowIndex, int columnIndex) {
                final Object result;
                if (columnIndex == 0) {
                    result = entries.get(rowIndex).getCredential().getCertSerialNo();
                } else if (columnIndex == 1) {
                    result = entries.get(rowIndex).getCredential().getIssuerDN();
                } else if (columnIndex == 2) {
                    result = entries.get(rowIndex).isAdmin();
                } else if (columnIndex == 3) {
                    result = entries.get(rowIndex).isAuditor();
                } else {
                    result = null;
                }
                return result;
            }

            @Override
            public String getColumnName(int column) {
                return COLUMN_NAMES[column];
            }

            @Override
            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return false;
            }

        });

        adminsTable.getSelectionModel().addListSelectionListener(
                new ListSelectionListener() {

            @Override
            public void valueChanged(final ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    final boolean enable
                            = adminsTable.getSelectedRowCount() == 1;
                    editButton.setEnabled(enable);
                    removeButton.setEnabled(enable);
                }
            }
        });
        refreshButton.doClick();
        
        // set initial state for the allow all checkbox
        boolean allowAnyWSAdmin = false;
        try {
            for (final WsGlobalConfiguration.Config.Entry entry :
                    SignServerAdminGUIApplication.getAdminWS().getGlobalConfiguration()
                    .getConfig().getEntry()) {
                if (entry.getKey().equals(GlobalConfiguration.SCOPE_GLOBAL + ALLOWANYWSADMIN)) {
                    allowAnyWSAdmin = Boolean.valueOf((String) entry.getValue());
                }
            }
        } catch (AdminNotAuthorizedException_Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Authorization denied", JOptionPane.ERROR_MESSAGE);
            allowAnyWSAdmin = false;
        }
        
        allowAnyCheckbox.setSelected(allowAnyWSAdmin);
        
        loadCurrentAdminCertButton.setEnabled(SignServerAdminGUIApplication.getAdminCertificate() != null);
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        editPanel = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        editCertSerialNoTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        editIssuerDNTextField = new javax.swing.JTextField();
        editRoleAdminRadio = new javax.swing.JRadioButton();
        editRoleAuditorRadio = new javax.swing.JRadioButton();
        editRoleBothRadio = new javax.swing.JRadioButton();
        jLabel3 = new javax.swing.JLabel();
        loadFromCertificateButton = new javax.swing.JButton();
        loadCurrentAdminCertButton = new javax.swing.JButton();
        buttonGroup1 = new javax.swing.ButtonGroup();
        jButton2 = new javax.swing.JButton();
        jButton3 = new javax.swing.JButton();
        jScrollPane6 = new javax.swing.JScrollPane();
        adminsTable = new javax.swing.JTable();
        addButton = new javax.swing.JButton();
        editButton = new javax.swing.JButton();
        removeButton = new javax.swing.JButton();
        jButton1 = new javax.swing.JButton();
        jToolBar1 = new javax.swing.JToolBar();
        refreshButton = new javax.swing.JButton();
        allowAnyCheckbox = new javax.swing.JCheckBox();

        editPanel.setName("editPanel"); // NOI18N

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(AdministratorsFrame.class);
        jLabel1.setText(resourceMap.getString("jLabel1.text")); // NOI18N
        jLabel1.setName("jLabel1"); // NOI18N

        editCertSerialNoTextField.setEditable(false);
        editCertSerialNoTextField.setText(resourceMap.getString("editCertSerialNoTextField.text")); // NOI18N
        editCertSerialNoTextField.setName("editCertSerialNoTextField"); // NOI18N

        jLabel2.setText(resourceMap.getString("jLabel2.text")); // NOI18N
        jLabel2.setName("jLabel2"); // NOI18N

        editIssuerDNTextField.setText(resourceMap.getString("editIssuerDNTextField.text")); // NOI18N
        editIssuerDNTextField.setName("editIssuerDNTextField"); // NOI18N

        buttonGroup1.add(editRoleAdminRadio);
        editRoleAdminRadio.setSelected(true);
        editRoleAdminRadio.setText(resourceMap.getString("editRoleAdminRadio.text")); // NOI18N
        editRoleAdminRadio.setName("editRoleAdminRadio"); // NOI18N

        buttonGroup1.add(editRoleAuditorRadio);
        editRoleAuditorRadio.setText(resourceMap.getString("editRoleAuditorRadio.text")); // NOI18N
        editRoleAuditorRadio.setName("editRoleAuditorRadio"); // NOI18N

        buttonGroup1.add(editRoleBothRadio);
        editRoleBothRadio.setText(resourceMap.getString("editRoleBothRadio.text")); // NOI18N
        editRoleBothRadio.setName("editRoleBothRadio"); // NOI18N

        jLabel3.setText(resourceMap.getString("jLabel3.text")); // NOI18N
        jLabel3.setName("jLabel3"); // NOI18N

        loadFromCertificateButton.setText(resourceMap.getString("loadFromCertificateButton.text")); // NOI18N
        loadFromCertificateButton.setName("loadFromCertificateButton"); // NOI18N
        loadFromCertificateButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadFromCertificateButtonPerformed(evt);
            }
        });

        loadCurrentAdminCertButton.setText(resourceMap.getString("loadCurrentAdminCertButton.text")); // NOI18N
        loadCurrentAdminCertButton.setName("loadCurrentAdminCertButton"); // NOI18N
        loadCurrentAdminCertButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadCurrentAdminCertButtonPerformed(evt);
            }
        });

        javax.swing.GroupLayout editPanelLayout = new javax.swing.GroupLayout(editPanel);
        editPanel.setLayout(editPanelLayout);
        editPanelLayout.setHorizontalGroup(
            editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(editPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(editPanelLayout.createSequentialGroup()
                        .addGroup(editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(editCertSerialNoTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 377, Short.MAX_VALUE)
                            .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, 377, Short.MAX_VALUE)
                            .addComponent(editIssuerDNTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 377, Short.MAX_VALUE)
                            .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, 377, Short.MAX_VALUE)
                            .addGroup(editPanelLayout.createSequentialGroup()
                                .addComponent(editRoleAdminRadio, javax.swing.GroupLayout.PREFERRED_SIZE, 110, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(editRoleAuditorRadio)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(editRoleBothRadio))
                            .addComponent(jLabel3, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 377, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(loadFromCertificateButton, javax.swing.GroupLayout.PREFERRED_SIZE, 111, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(loadCurrentAdminCertButton, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 97, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        editPanelLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {editRoleAdminRadio, editRoleAuditorRadio, editRoleBothRadio});

        editPanelLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {loadCurrentAdminCertButton, loadFromCertificateButton});

        editPanelLayout.setVerticalGroup(
            editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(editPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(editCertSerialNoTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(loadFromCertificateButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(loadCurrentAdminCertButton)
                .addGap(9, 9, 9)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(editIssuerDNTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(editRoleAdminRadio)
                    .addComponent(editRoleAuditorRadio)
                    .addComponent(editRoleBothRadio))
                .addContainerGap())
        );

        jButton2.setText(resourceMap.getString("jButton2.text")); // NOI18N
        jButton2.setName("jButton2"); // NOI18N

        jButton3.setText(resourceMap.getString("jButton3.text")); // NOI18N
        jButton3.setName("jButton3"); // NOI18N

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle(resourceMap.getString("Form.title")); // NOI18N
        setLocationByPlatform(true);
        setName("Form"); // NOI18N

        jScrollPane6.setVerticalScrollBarPolicy(javax.swing.ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        jScrollPane6.setName("jScrollPane6"); // NOI18N

        adminsTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Certificate serial number", "Issuer DN"
            }
        ));
        adminsTable.setName("adminsTable"); // NOI18N
        jScrollPane6.setViewportView(adminsTable);

        addButton.setText(resourceMap.getString("addButton.text")); // NOI18N
        addButton.setName("addButton"); // NOI18N
        addButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addButtonActionPerformed(evt);
            }
        });

        editButton.setText(resourceMap.getString("editButton.text")); // NOI18N
        editButton.setEnabled(false);
        editButton.setName("editButton"); // NOI18N
        editButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editButtonActionPerformed(evt);
            }
        });

        removeButton.setText(resourceMap.getString("removeButton.text")); // NOI18N
        removeButton.setEnabled(false);
        removeButton.setName("removeButton"); // NOI18N
        removeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removeButtonActionPerformed(evt);
            }
        });

        jButton1.setText(resourceMap.getString("jButton1.text")); // NOI18N
        jButton1.setName("jButton1"); // NOI18N
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        jToolBar1.setRollover(true);
        jToolBar1.setName("jToolBar1"); // NOI18N

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getActionMap(AdministratorsFrame.class, this);
        refreshButton.setAction(actionMap.get("reloadGlobalConfiguration")); // NOI18N
        refreshButton.setText(resourceMap.getString("refreshButton.text")); // NOI18N
        refreshButton.setFocusable(false);
        refreshButton.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        refreshButton.setName("refreshButton"); // NOI18N
        refreshButton.setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);
        jToolBar1.add(refreshButton);

        allowAnyCheckbox.setText(resourceMap.getString("allowAnyCheckbox.text")); // NOI18N
        allowAnyCheckbox.setName("allowAnyCheckbox"); // NOI18N
        allowAnyCheckbox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                allowAnyCheckboxActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jToolBar1, javax.swing.GroupLayout.DEFAULT_SIZE, 770, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 660, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(addButton)
                            .addComponent(editButton)
                            .addComponent(removeButton, javax.swing.GroupLayout.PREFERRED_SIZE, 98, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 64, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(allowAnyCheckbox))
                .addContainerGap())
        );

        layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {addButton, editButton, removeButton});

        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jToolBar1, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addComponent(addButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(editButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(removeButton))
                    .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 240, Short.MAX_VALUE))
                .addGap(1, 1, 1)
                .addComponent(allowAnyCheckbox)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton1)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void addButtonActionPerformed(ActionEvent evt) {//GEN-FIRST:event_addButtonActionPerformed
        try {
            editCertSerialNoTextField.setText("");
            editCertSerialNoTextField.setEditable(true);
            editIssuerDNTextField.setText("");
            
            final int res = JOptionPane.showConfirmDialog(this, editPanel,
                    "Add property", JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE);
            if (res == JOptionPane.OK_OPTION) {
                final boolean admin = editRoleBothRadio.isSelected() || editRoleAdminRadio.isSelected();
                final boolean auditor = editRoleBothRadio.isSelected() || editRoleAuditorRadio.isSelected();
                
                final String certSerialNo = editCertSerialNoTextField.getText();
                final String issuerDN = editIssuerDNTextField.getText();

                final HashMap<Credential, Entry> admins = parseAdmins();
                final Credential cred = new Credential(certSerialNo, issuerDN);
                
                if (admins.containsKey(cred)) {
                    JOptionPane.showMessageDialog(this,
                            "The administrator already existed");
                } else {
                    final Entry newEntry = new Entry(cred, admin, auditor);
                    admins.put(cred, newEntry);

                    if (admin) {
                        SignServerAdminGUIApplication.getAdminWS()
                            .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                            "WSADMINS",
                            serializeAdmins(admins));
                    }
                    if (auditor) {
                        SignServerAdminGUIApplication.getAdminWS()
                            .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                            "WSAUDITORS",
                            serializeAuditors(admins));
                    }
                }
                refreshButton.doClick();
            }
        } catch (AdminNotAuthorizedException_Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Authorization denied", JOptionPane.ERROR_MESSAGE);
        }
}//GEN-LAST:event_addButtonActionPerformed

    private void editButtonActionPerformed(ActionEvent evt) {//GEN-FIRST:event_editButtonActionPerformed
        try {
            final int row = adminsTable.getSelectedRow();

            if (row != -1) {
                final Entry oldEntry = entries.get(row);

                editCertSerialNoTextField.setText(oldEntry.getCredential().getCertSerialNo());
                editCertSerialNoTextField.setEditable(true);
                editIssuerDNTextField.setText(oldEntry.getCredential().getIssuerDN());
                editRoleAdminRadio.setSelected(oldEntry.isAdmin());
                editRoleAuditorRadio.setSelected(oldEntry.isAuditor());
                editRoleBothRadio.setSelected(oldEntry.isAdmin() && oldEntry.isAuditor());

                final int res = JOptionPane.showConfirmDialog(this, editPanel,
                        "Edit administrator", JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.PLAIN_MESSAGE);
                if (res == JOptionPane.OK_OPTION) {
                    
                    HashMap<Credential, Entry> admins = parseAdmins();
                    
                    final Credential newCred = new Credential(editCertSerialNoTextField.getText(), 
                            editIssuerDNTextField.getText());

                    if (!admins.containsKey(oldEntry.getCredential())) {
                        JOptionPane.showMessageDialog(this,
                                "No such administrator");
                    } else {
                        admins.remove(oldEntry.getCredential());
                        
                        final Entry newEntry = new Entry(newCred, editRoleAdminRadio.isSelected() || editRoleBothRadio.isSelected(), editRoleAuditorRadio.isSelected() || editRoleBothRadio.isSelected());
                        
                        if (admins.containsKey(newCred)) {
                            JOptionPane.showMessageDialog(this,
                            "The administrator already existed");
                        } else {
                            admins.put(newCred, newEntry);
                        }
                        SignServerAdminGUIApplication.getAdminWS()
                            .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                            "WSADMINS",
                            serializeAdmins(admins));
                        SignServerAdminGUIApplication.getAdminWS()
                            .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                            "WSAUDITORS",
                            serializeAuditors(admins));
                    }
                    refreshButton.doClick();
                }
            }
        } catch (AdminNotAuthorizedException_Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Authorization denied", JOptionPane.ERROR_MESSAGE);
        }
}//GEN-LAST:event_editButtonActionPerformed

    private void removeButtonActionPerformed(ActionEvent evt) {//GEN-FIRST:event_removeButtonActionPerformed
        try {
            final int row = adminsTable.getSelectedRow();

            if (row != -1) {
                final int res = JOptionPane.showConfirmDialog(this,
                        "Are you sure you want to remove the administrator?",
                        "Remove administrator", JOptionPane.YES_NO_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE);
                if (res == JOptionPane.YES_OPTION) {
                    final Entry oldEntry = entries.get(row);
                    HashMap<Credential, Entry> admins = parseAdmins();

                    if (!admins.containsKey(oldEntry.getCredential())) {
                        JOptionPane.showMessageDialog(this,
                                "No such administrator");
                    } else {
                        admins.remove(oldEntry.getCredential());

                        if (oldEntry.isAdmin()) {
                            SignServerAdminGUIApplication.getAdminWS()
                                .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                "WSADMINS",
                                serializeAdmins(admins));
                        }
                        if (oldEntry.isAuditor()) {
                            SignServerAdminGUIApplication.getAdminWS()
                                .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                "WSAUDITORS",
                                serializeAuditors(admins));
                        }
                    }
                    refreshButton.doClick();
                }
            }
        } catch (AdminNotAuthorizedException_Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Authorization denied", JOptionPane.ERROR_MESSAGE);
        }
}//GEN-LAST:event_removeButtonActionPerformed

    private void jButton1ActionPerformed(ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        dispose();
    }//GEN-LAST:event_jButton1ActionPerformed

    private void loadFromCertificateButtonPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadFromCertificateButtonPerformed
        Utils.selectAndLoadFromCert(editPanel, editCertSerialNoTextField, editIssuerDNTextField);
    }//GEN-LAST:event_loadFromCertificateButtonPerformed

    private void allowAnyCheckboxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_allowAnyCheckboxActionPerformed
        final boolean checked = allowAnyCheckbox.isSelected();
        
        try {
            if (checked) {
                // show confirmation for security reasons
                final int res =
                        JOptionPane.showConfirmDialog(this,
                                "About to change to allow any administrator with a valid certificate even if they are not listed.",
                                "Allow any administrator", JOptionPane.OK_CANCEL_OPTION,
                                JOptionPane.QUESTION_MESSAGE);

                if (res == JOptionPane.OK_OPTION) {
                    SignServerAdminGUIApplication.getAdminWS()
                        .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                   ALLOWANYWSADMIN, Boolean.TRUE.toString());
                } else {
                    // revert back on cancel
                    allowAnyCheckbox.setSelected(false);
                }
            } else {
                // show confirmation because of potential admin lock-out
                final int res =
                        JOptionPane.showConfirmDialog(this,
                                "About to change to only allow listed administrators.\n"
                                +"First make sure you are listed as an Administrator otherwise you will be logged out without the ability to login except from command line interface.",
                                "Allow only listed administrators", JOptionPane.OK_CANCEL_OPTION,
                                JOptionPane.QUESTION_MESSAGE);
                
                if (res == JOptionPane.OK_OPTION) {
                    SignServerAdminGUIApplication.getAdminWS()
                        .removeGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL, ALLOWANYWSADMIN);
                } else {
                    // revert back on cancel
                    allowAnyCheckbox.setSelected(true);
                }
            }
        } catch (AdminNotAuthorizedException_Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Authorization denied", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_allowAnyCheckboxActionPerformed

    private void loadCurrentAdminCertButtonPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadCurrentAdminCertButtonPerformed
        X509Certificate cert = SignServerAdminGUIApplication.getAdminCertificate();
        if (cert != null) {
            editCertSerialNoTextField.setText(cert.getSerialNumber().toString(16));
            editIssuerDNTextField.setText(cert.getIssuerDN().getName());
        }
    }//GEN-LAST:event_loadCurrentAdminCertButtonPerformed

    @Action(block = Task.BlockingScope.WINDOW)
    public Task reloadGlobalConfiguration() {
        return new ReloadGlobalConfigurationTask(org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class));
    }

    private class ReloadGlobalConfigurationTask extends Task<List<Entry>, Void> {
        ReloadGlobalConfigurationTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to ReloadGlobalConfigurationTask fields, here.
            super(app);
        }
        @Override protected List<Entry> doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            List<Entry> result = null;

            try {
               result = new ArrayList<Entry>(parseAdmins().values());
            } catch (final AdminNotAuthorizedException_Exception ex) {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        JOptionPane.showMessageDialog(
                                AdministratorsFrame.this, ex.getMessage(),
                        "Authorization denied", JOptionPane.ERROR_MESSAGE);
                    }
                });
            }
            // return your result
            return result;
        }
        @Override protected void succeeded(List<Entry> result) {
            // Runs on the EDT.  Update the GUI based on
            // the result computed by doInBackground().

            if (result == null) {
                result = Collections.emptyList();
            }
            entries = result;
            adminsTable.revalidate();
        }
    }


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addButton;
    private javax.swing.JTable adminsTable;
    private javax.swing.JCheckBox allowAnyCheckbox;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JButton editButton;
    private javax.swing.JTextField editCertSerialNoTextField;
    private javax.swing.JTextField editIssuerDNTextField;
    private javax.swing.JPanel editPanel;
    private javax.swing.JRadioButton editRoleAdminRadio;
    private javax.swing.JRadioButton editRoleAuditorRadio;
    private javax.swing.JRadioButton editRoleBothRadio;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JToolBar jToolBar1;
    private javax.swing.JButton loadCurrentAdminCertButton;
    private javax.swing.JButton loadFromCertificateButton;
    private javax.swing.JButton refreshButton;
    private javax.swing.JButton removeButton;
    // End of variables declaration//GEN-END:variables

    private LinkedHashMap<Credential, Entry> parseAdmins()
            throws AdminNotAuthorizedException_Exception {
        String admins = null;
        String auditors = null;

        for (WsGlobalConfiguration.Config.Entry entry
                    : SignServerAdminGUIApplication.getAdminWS()
                        .getGlobalConfiguration().getConfig().getEntry()) {
            if (entry.getKey().equals(GlobalConfiguration.SCOPE_GLOBAL
                    + "WSADMINS")) {
                admins = (String) entry.getValue();
            } else if (entry.getKey().equals(GlobalConfiguration.SCOPE_GLOBAL
                    + "WSAUDITORS")) {
                auditors = (String) entry.getValue();
            }
        }

        final LinkedHashMap<Credential, Entry> entryMap = new LinkedHashMap<Credential, Entry>();

        // Admins
        if (admins != null && admins.contains(";")) {
            for (String entryString : admins.split(";")) {
                final String[] parts = entryString.split(",", 2);
                final Credential cred = new Credential(parts[0], parts[1]);
                Entry entry = entryMap.get(cred);
                if (entry == null) {
                    entry = new Entry(cred);
                    entryMap.put(cred, entry);
                }
                entry.setAdmin(true);
            }
        }

        // Auditors
        if (auditors != null && auditors.contains(";")) {
            for (String entryString : auditors.split(";")) {
                final String[] parts = entryString.split(",", 2);
                final Credential cred = new Credential(parts[0], parts[1]);
                Entry entry = entryMap.get(cred);
                if (entry == null) {
                    entry = new Entry(cred);
                    entryMap.put(cred, entry);
                }
                entry.setAuditor(true);
            }
        }

        return entryMap;
    }

    private static String serializeAdmins(final Map<Credential, Entry> entries) {
        final StringBuilder buff = new StringBuilder();
        for (Entry entry : entries.values()) {
            if (entry.isAdmin()) {
                buff.append(entry.getCredential().getCertSerialNo());
                buff.append(",");
                buff.append(entry.getCredential().getIssuerDN());
                buff.append(";");
            }
        }
        return buff.toString();
    }
    
    private static String serializeAuditors(final Map<Credential, Entry> entries) {
        final StringBuilder buff = new StringBuilder();
        for (Entry entry : entries.values()) {
            if (entry.isAuditor()) {
                buff.append(entry.getCredential().getCertSerialNo());
                buff.append(",");
                buff.append(entry.getCredential().getIssuerDN());
                buff.append(";");
            }
        }
        return buff.toString();
    }
    
    private static class Credential {
        private String certSerialNo;
        private String issuerDN;

        public Credential(String certSerialNo, String issuerDN) {
            this.certSerialNo = certSerialNo;
            this.issuerDN = issuerDN;
        }

        public String getCertSerialNo() {
            return certSerialNo;
        }

        public String getIssuerDN() {
            return issuerDN;
        }

        @Override
        public int hashCode() {
            int hash = 7;
            hash = 59 * hash + (this.certSerialNo != null ? this.certSerialNo.hashCode() : 0);
            hash = 59 * hash + (this.issuerDN != null ? this.issuerDN.hashCode() : 0);
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final Credential other = (Credential) obj;
            if ((this.certSerialNo == null) ? (other.certSerialNo != null) : !this.certSerialNo.equals(other.certSerialNo)) {
                return false;
            }
            if ((this.issuerDN == null) ? (other.issuerDN != null) : !this.issuerDN.equals(other.issuerDN)) {
                return false;
            }
            return true;
        }
        
    }

    private static class Entry {
        
        private final Credential credential;
        private boolean admin;
        private boolean auditor;

        public Entry(final Credential credential, final boolean admin, final boolean auditor) {
            this.credential = credential;
            this.admin = admin;
            this.auditor = auditor;
        }

        private Entry(final Credential cred) {
            this.credential = cred;
        }

        public Credential getCredential() {
            return credential;
        }

        public boolean isAdmin() {
            return admin;
        }

        public boolean isAuditor() {
            return auditor;
        }

        public void setAdmin(boolean admin) {
            this.admin = admin;
        }

        public void setAuditor(boolean auditor) {
            this.auditor = auditor;
        }

        @Override
        public int hashCode() {
            int hash = 7;
            hash = 53 * hash + (this.credential != null ? this.credential.hashCode() : 0);
            hash = 53 * hash + (this.admin ? 1 : 0);
            hash = 53 * hash + (this.auditor ? 1 : 0);
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final Entry other = (Entry) obj;
            if (this.credential != other.credential && (this.credential == null || !this.credential.equals(other.credential))) {
                return false;
            }
            if (this.admin != other.admin) {
                return false;
            }
            if (this.auditor != other.auditor) {
                return false;
            }
            return true;
        }

    }
}
