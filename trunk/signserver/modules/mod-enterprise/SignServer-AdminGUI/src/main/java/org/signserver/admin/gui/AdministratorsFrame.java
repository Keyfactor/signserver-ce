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
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import javax.ejb.EJBException;
import javax.swing.JComboBox;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;
import javax.xml.ws.soap.SOAPFaultException;
import org.apache.log4j.Logger;
import org.jdesktop.application.Action;
import org.jdesktop.application.Task;
import org.signserver.admin.common.roles.AdminEntry;
import org.signserver.admin.common.roles.AdminsUtil;
import org.signserver.admin.gui.adminws.gen
        .AdminNotAuthorizedException_Exception;
import org.signserver.admin.gui.adminws.gen.WsGlobalConfiguration;
import org.signserver.common.ClientEntry;
import  org.signserver.common.GlobalConfiguration;
import org.signserver.common.SignServerUtil;

/**
 * Frame for viewing and editing global configuration properties.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@SuppressWarnings("PMD.UnusedFormalParameter")
public class AdministratorsFrame extends javax.swing.JFrame {
    /** Logger for this class */
    private static final Logger LOG = Logger.getLogger(AdministratorsFrame.class);

    private static final String[] COLUMN_NAMES = new String[] {
        "Certificate serial number",
        "Issuer DN",
        "Admin",
        "Auditor",
        "Archive Auditor",
        "Peer System"
    };

    private static final String ALLOWANYWSADMIN = "ALLOWANYWSADMIN";
    
    private List<AdminEntry> entries = Collections.emptyList();

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
                if (columnIndex == 2 || columnIndex == 3 || columnIndex == 4 || columnIndex == 5) {
                    return Boolean.class;
                }
                return super.getColumnClass(columnIndex);
            }

            @Override
            public Object getValueAt(int rowIndex, int columnIndex) {
                final Object result;
                switch (columnIndex) {
                    case 0:
                        result = entries.get(rowIndex).getClient().getSerialNumber().toString(16);
                        break;
                    case 1:
                        result = entries.get(rowIndex).getClient().getIssuerDN();
                        break;
                    case 2:
                        result = entries.get(rowIndex).isAdmin();
                        break;
                    case 3:
                        result = entries.get(rowIndex).isAuditor();
                        break;
                    case 4:
                        result = entries.get(rowIndex).isArchiveAuditor();
                        break;
                    case 5:
                        result = entries.get(rowIndex).isPeerSystem();
                        break;
                    default:
                        result = null;
                        break;
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
        adminsTable.setRowHeight(new JComboBox/*<String>*/().getPreferredSize().height);
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
        
        certificateSerialNumberErrorLabel.setVisible(false);
        issuerErrorLabel.setVisible(false);
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
        jLabel3 = new javax.swing.JLabel();
        loadFromCertificateButton = new javax.swing.JButton();
        loadCurrentAdminCertButton = new javax.swing.JButton();
        editRoleAdministratorCheckBox = new javax.swing.JCheckBox();
        editRoleAuditorCheckBox = new javax.swing.JCheckBox();
        editRoleArchiveAuditorCheckBox = new javax.swing.JCheckBox();
        certificateSerialNumberErrorLabel = new javax.swing.JLabel();
        issuerErrorLabel = new javax.swing.JLabel();
        editRolePeerSystemCheckBox = new javax.swing.JCheckBox();
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

        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance().getContext().getResourceMap(AdministratorsFrame.class);
        jLabel1.setText(resourceMap.getString("jLabel1.text")); // NOI18N
        jLabel1.setName("jLabel1"); // NOI18N

        editCertSerialNoTextField.setEditable(false);
        editCertSerialNoTextField.setText(resourceMap.getString("editCertSerialNoTextField.text")); // NOI18N
        editCertSerialNoTextField.setName("editCertSerialNoTextField"); // NOI18N

        jLabel2.setText(resourceMap.getString("jLabel2.text")); // NOI18N
        jLabel2.setName("jLabel2"); // NOI18N

        editIssuerDNTextField.setText(resourceMap.getString("editIssuerDNTextField.text")); // NOI18N
        editIssuerDNTextField.setName("editIssuerDNTextField"); // NOI18N

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

        editRoleAdministratorCheckBox.setSelected(true);
        editRoleAdministratorCheckBox.setText(resourceMap.getString("editRoleAdministratorCheckBox.text")); // NOI18N
        editRoleAdministratorCheckBox.setName("editRoleAdministratorCheckBox"); // NOI18N

        editRoleAuditorCheckBox.setText(resourceMap.getString("editRoleAuditorCheckBox.text")); // NOI18N
        editRoleAuditorCheckBox.setName("editRoleAuditorCheckBox"); // NOI18N

        editRoleArchiveAuditorCheckBox.setText(resourceMap.getString("editRoleArchiveAuditorCheckBox.text")); // NOI18N
        editRoleArchiveAuditorCheckBox.setName("editRoleArchiveAuditorCheckBox"); // NOI18N

        certificateSerialNumberErrorLabel.setForeground(resourceMap.getColor("certificateSerialNumberErrorLabel.foreground")); // NOI18N
        certificateSerialNumberErrorLabel.setText(resourceMap.getString("certificateSerialNumberErrorLabel.text")); // NOI18N
        certificateSerialNumberErrorLabel.setName("certificateSerialNumberErrorLabel"); // NOI18N

        issuerErrorLabel.setForeground(resourceMap.getColor("issuerErrorLabel.foreground")); // NOI18N
        issuerErrorLabel.setText(resourceMap.getString("issuerErrorLabel.text")); // NOI18N
        issuerErrorLabel.setName("issuerErrorLabel"); // NOI18N

        editRolePeerSystemCheckBox.setText(resourceMap.getString("editRolePeerSystemCheckBox.text")); // NOI18N
        editRolePeerSystemCheckBox.setName("editRolePeerSystemCheckBox"); // NOI18N

        javax.swing.GroupLayout editPanelLayout = new javax.swing.GroupLayout(editPanel);
        editPanel.setLayout(editPanelLayout);
        editPanelLayout.setHorizontalGroup(
            editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(editPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, editPanelLayout.createSequentialGroup()
                        .addComponent(certificateSerialNumberErrorLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 743, Short.MAX_VALUE)
                        .addGap(18, 18, 18)
                        .addComponent(loadCurrentAdminCertButton, javax.swing.GroupLayout.PREFERRED_SIZE, 97, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(editPanelLayout.createSequentialGroup()
                        .addComponent(editRoleAdministratorCheckBox)
                        .addGap(18, 18, 18)
                        .addComponent(editRoleAuditorCheckBox)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(editRoleArchiveAuditorCheckBox)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(editRolePeerSystemCheckBox))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, editPanelLayout.createSequentialGroup()
                        .addGroup(editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(issuerErrorLabel, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 749, Short.MAX_VALUE)
                            .addComponent(editCertSerialNoTextField, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 749, Short.MAX_VALUE)
                            .addComponent(jLabel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 749, Short.MAX_VALUE)
                            .addComponent(editIssuerDNTextField, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 749, Short.MAX_VALUE)
                            .addComponent(jLabel2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 749, Short.MAX_VALUE)
                            .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, 749, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(loadFromCertificateButton, javax.swing.GroupLayout.PREFERRED_SIZE, 111, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );

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
                .addGroup(editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(loadCurrentAdminCertButton)
                    .addComponent(certificateSerialNumberErrorLabel))
                .addGap(9, 9, 9)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(editIssuerDNTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(issuerErrorLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 45, Short.MAX_VALUE)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(editPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(editRoleAdministratorCheckBox)
                    .addComponent(editRoleAuditorCheckBox)
                    .addComponent(editRoleArchiveAuditorCheckBox)
                    .addComponent(editRolePeerSystemCheckBox))
                .addGap(12, 12, 12))
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

        javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance().getContext().getActionMap(AdministratorsFrame.class, this);
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
                    .addComponent(jToolBar1, javax.swing.GroupLayout.DEFAULT_SIZE, 1412, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 1302, Short.MAX_VALUE)
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

    /**
     * Utility method to determine if a string represents a valid serial numer
     * in hexadecimal format.
     * 
     * @param serial String representing a serial number
     * @return True if given string is valid
     */
    private boolean isValidSerialNumber(final String serial) {
        try {
            final BigInteger serialNumber = new BigInteger(serial, 16);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
    
    /**
     * Show administrator add/edit dialog.
     * 
     * @param serialNumberInvalid Set to true to indicate a previously entered
     *                            invalid serial number
     * @param issuerInvalid Set to true to indicate a previously entered invalid
     *                      issuer DN
     * @return Dialog selection @see JOptionPane.showConfirmDialog
     */
    private int showConfirmDialog(final boolean serialNumberInvalid,
                                  final boolean issuerInvalid) {
        certificateSerialNumberErrorLabel.setVisible(serialNumberInvalid);
        issuerErrorLabel.setVisible(issuerInvalid);
        
        return JOptionPane.showConfirmDialog(this, editPanel,
                        "Edit administrator", JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.PLAIN_MESSAGE);
    }
    
    private void addButtonActionPerformed(ActionEvent evt) {//GEN-FIRST:event_addButtonActionPerformed
        try {
            editCertSerialNoTextField.setText("");
            editCertSerialNoTextField.setEditable(true);
            editIssuerDNTextField.setText("");
            
            boolean serialNumberInvalid = false;
            boolean issuerInvalid = false;
            
            for (;;) {
                final int res =
                            showConfirmDialog(serialNumberInvalid, issuerInvalid);

                if (res == JOptionPane.OK_OPTION) {
                    final boolean admin = editRoleAdministratorCheckBox.isSelected();
                    final boolean auditor = editRoleAuditorCheckBox.isSelected();
                    final boolean archiveAuditor = editRoleArchiveAuditorCheckBox.isSelected();
                    final boolean peerSystem = editRolePeerSystemCheckBox.isSelected();

                    final String certSerialNo = editCertSerialNoTextField.getText();
                    final String issuerDN = editIssuerDNTextField.getText();

                    serialNumberInvalid =
                            !isValidSerialNumber(certSerialNo);
                    issuerInvalid = issuerDN.isEmpty();

                    if (!serialNumberInvalid && !issuerInvalid) {
                    
                        final HashMap<ClientEntry, AdminEntry> admins = parseAdmins();
                        final ClientEntry cred =
                                new ClientEntry(new BigInteger(certSerialNo, 16),
                                                issuerDN);

                        if (admins.containsKey(cred)) {
                            JOptionPane.showMessageDialog(this,
                                    "The administrator already existed");
                        } else {
                            final AdminEntry newEntry =
                                    new AdminEntry(cred, admin, auditor, archiveAuditor, peerSystem);
                            admins.put(cred, newEntry);

                            if (auditor) {
                                SignServerAdminGUIApplication.getAdminWS()
                                    .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                    "WSAUDITORS",
                                    AdminsUtil.serializeAuditors(admins));
                            }
                            if (archiveAuditor) {
                                SignServerAdminGUIApplication.getAdminWS()
                                    .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                    "WSARCHIVEAUDITORS",
                                    AdminsUtil.serializeArchiveAuditors(admins));
                            }
                            if (peerSystem) {
                                SignServerAdminGUIApplication.getAdminWS()
                                    .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                    "WSPEERS",
                                    AdminsUtil.serializePeerSystems(admins));
                            }
                            if (admin) {
                                SignServerAdminGUIApplication.getAdminWS()
                                    .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                    "WSADMINS",
                                    AdminsUtil.serializeAdmins(admins));
                            }
                        }
                        break;
                    }
                } else {
                    break;
                }
            }
            refreshButton.doClick();
        } catch (AdminNotAuthorizedException_Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Authorization denied", JOptionPane.ERROR_MESSAGE);
        } catch (SOAPFaultException | EJBException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                "Operation failed on server side", JOptionPane.ERROR_MESSAGE);
        }
}//GEN-LAST:event_addButtonActionPerformed


    
    private void editButtonActionPerformed(ActionEvent evt) {//GEN-FIRST:event_editButtonActionPerformed
        try {
            final int row = adminsTable.getSelectedRow();

            if (row != -1) {
                final AdminEntry oldEntry = entries.get(row);

                editCertSerialNoTextField.setText(oldEntry.getClient().getSerialNumber().toString(16));
                editCertSerialNoTextField.setEditable(true);
                editIssuerDNTextField.setText(oldEntry.getClient().getIssuerDN());
                editRoleAdministratorCheckBox.setSelected(oldEntry.isAdmin());
                editRoleAuditorCheckBox.setSelected(oldEntry.isAuditor());
                editRoleArchiveAuditorCheckBox.setSelected(oldEntry.isArchiveAuditor());
                editRolePeerSystemCheckBox.setSelected(oldEntry.isPeerSystem());

                boolean serialNumberInvalid = false;
                boolean issuerInvalid = false;
                
                for (;;) {
                    final int res =
                            showConfirmDialog(serialNumberInvalid, issuerInvalid);
                    if (res == JOptionPane.OK_OPTION) {
                        final String certSerialNumber =
                                editCertSerialNoTextField.getText();
                        final String issuerDN =
                                editIssuerDNTextField.getText();

                        serialNumberInvalid =
                                !isValidSerialNumber(certSerialNumber);
                        issuerInvalid = issuerDN.isEmpty();
                        
                        if (!serialNumberInvalid && !issuerInvalid) {
                            HashMap<ClientEntry, AdminEntry> admins = parseAdmins();

                            final ClientEntry newCred =
                                    new ClientEntry(new BigInteger(certSerialNumber,
                                                                   16), 
                                                    issuerDN);

                            if (!admins.containsKey(oldEntry.getClient())) {
                                JOptionPane.showMessageDialog(this,
                                        "No such administrator");
                            } else {
                                admins.remove(oldEntry.getClient());

                                final AdminEntry newEntry =
                                        new AdminEntry(newCred,
                                            editRoleAdministratorCheckBox.isSelected(),
                                            editRoleAuditorCheckBox.isSelected(),
                                            editRoleArchiveAuditorCheckBox.isSelected(),
                                            editRolePeerSystemCheckBox.isSelected());

                                if (admins.containsKey(newCred)) {
                                    JOptionPane.showMessageDialog(this,
                                    "The administrator already existed");
                                } else {
                                    admins.put(newCred, newEntry);
                                }
                                SignServerAdminGUIApplication.getAdminWS()
                                    .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                    "WSAUDITORS",
                                    AdminsUtil.serializeAuditors(admins));
                                SignServerAdminGUIApplication.getAdminWS()
                                    .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                    "WSARCHIVEAUDITORS",
                                    AdminsUtil.serializeArchiveAuditors(admins));
                                SignServerAdminGUIApplication.getAdminWS()
                                    .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                    "WSPEERS",
                                    AdminsUtil.serializePeerSystems(admins));
                                SignServerAdminGUIApplication.getAdminWS()
                                    .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                    "WSADMINS",
                                    AdminsUtil.serializeAdmins(admins));
                            }
                            break;
                        }
                    } else {
                        break;
                    }
                }
                refreshButton.doClick();
            }
        } catch (AdminNotAuthorizedException_Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Authorization denied", JOptionPane.ERROR_MESSAGE);
        } catch (SOAPFaultException | EJBException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                "Operation failed on server side", JOptionPane.ERROR_MESSAGE);
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
                    final AdminEntry oldEntry = entries.get(row);
                    HashMap<ClientEntry, AdminEntry> admins = parseAdmins();

                    if (!admins.containsKey(oldEntry.getClient())) {
                        JOptionPane.showMessageDialog(this,
                                "No such administrator");
                    } else {
                        admins.remove(oldEntry.getClient());

                        if (oldEntry.isAuditor()) {
                            SignServerAdminGUIApplication.getAdminWS()
                                .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                "WSAUDITORS",
                                AdminsUtil.serializeAuditors(admins));
                        }
                        if (oldEntry.isArchiveAuditor()) {
                            SignServerAdminGUIApplication.getAdminWS()
                                .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                "WSARCHIVEAUDITORS",
                                AdminsUtil.serializeArchiveAuditors(admins));
                        }
                        if (oldEntry.isPeerSystem()) {
                            SignServerAdminGUIApplication.getAdminWS()
                                .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                "WSPEERS",
                                AdminsUtil.serializePeerSystems(admins));
                        }
                        if (oldEntry.isAdmin()) {
                            SignServerAdminGUIApplication.getAdminWS()
                                .setGlobalProperty(GlobalConfiguration.SCOPE_GLOBAL,
                                "WSADMINS",
                                AdminsUtil.serializeAdmins(admins));
                        }
                    }
                    refreshButton.doClick();
                }
            }
        } catch (AdminNotAuthorizedException_Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                    "Authorization denied", JOptionPane.ERROR_MESSAGE);
        } catch (SOAPFaultException | EJBException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                "Operation failed on server side", JOptionPane.ERROR_MESSAGE);
        }
}//GEN-LAST:event_removeButtonActionPerformed

    private void jButton1ActionPerformed(ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        dispose();
    }//GEN-LAST:event_jButton1ActionPerformed

    private void loadFromCertificateButtonPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadFromCertificateButtonPerformed
        Utils.selectAndLoadFromCert(editPanel, editCertSerialNoTextField,
                editIssuerDNTextField, true);
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
        } catch (SOAPFaultException | EJBException ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(),
                "Operation failed on server side", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_allowAnyCheckboxActionPerformed

    private void loadCurrentAdminCertButtonPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadCurrentAdminCertButtonPerformed
        X509Certificate cert = SignServerAdminGUIApplication.getAdminCertificate();
        if (cert != null) {
            editCertSerialNoTextField.setText(cert.getSerialNumber().toString(16));
            editIssuerDNTextField.setText(getIssuerDN(cert));
        }
    }//GEN-LAST:event_loadCurrentAdminCertButtonPerformed

    /** @return The issuer DN formatted as expected by the AdminWS */
    private String getIssuerDN(X509Certificate certificate) {
        String dn = certificate.getIssuerX500Principal().getName();
        SignServerUtil.BasicX509NameTokenizer tok =
                new SignServerUtil.BasicX509NameTokenizer(dn);
        StringBuilder buf = new StringBuilder();
        while (tok.hasMoreTokens()) {
            final String token = tok.nextToken();
            buf.append(token);
            if (tok.hasMoreTokens()) {
                buf.append(", ");
            }
        }
        return buf.toString();
    }
    
    
    @Action(block = Task.BlockingScope.WINDOW)
    public Task reloadGlobalConfiguration() {
        return new ReloadGlobalConfigurationTask(org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class));
    }

    private class ReloadGlobalConfigurationTask extends Task<List<AdminEntry>, Void> {
        ReloadGlobalConfigurationTask(org.jdesktop.application.Application app) {
            // Runs on the EDT.  Copy GUI state that
            // doInBackground() depends on from parameters
            // to ReloadGlobalConfigurationTask fields, here.
            super(app);
        }
        @Override protected List<AdminEntry> doInBackground() {
            // Your Task's code here.  This method runs
            // on a background thread, so don't reference
            // the Swing GUI from here.
            List<AdminEntry> result = null;

            try {
               result = new ArrayList<>(parseAdmins().values());
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
        @Override protected void succeeded(List<AdminEntry> result) {
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
    private javax.swing.JLabel certificateSerialNumberErrorLabel;
    private javax.swing.JButton editButton;
    private javax.swing.JTextField editCertSerialNoTextField;
    private javax.swing.JTextField editIssuerDNTextField;
    private javax.swing.JPanel editPanel;
    private javax.swing.JCheckBox editRoleAdministratorCheckBox;
    private javax.swing.JCheckBox editRoleArchiveAuditorCheckBox;
    private javax.swing.JCheckBox editRoleAuditorCheckBox;
    private javax.swing.JCheckBox editRolePeerSystemCheckBox;
    private javax.swing.JLabel issuerErrorLabel;
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

    private LinkedHashMap<ClientEntry, AdminEntry> parseAdmins()
            throws AdminNotAuthorizedException_Exception {
        String admins = null;
        String auditors = null;
        String archiveAuditors = null;
        String peerSystems = null;

        for (WsGlobalConfiguration.Config.Entry entry
                    : SignServerAdminGUIApplication.getAdminWS()
                        .getGlobalConfiguration().getConfig().getEntry()) {
            if (entry.getKey().equals(GlobalConfiguration.SCOPE_GLOBAL
                    + "WSADMINS")) {
                admins = (String) entry.getValue();
            } else if (entry.getKey().equals(GlobalConfiguration.SCOPE_GLOBAL
                    + "WSAUDITORS")) {
                auditors = (String) entry.getValue();
            } else if (entry.getKey().equals(GlobalConfiguration.SCOPE_GLOBAL
                    + "WSARCHIVEAUDITORS")) {
                archiveAuditors = (String) entry.getValue();
            } else if (entry.getKey().equals(GlobalConfiguration.SCOPE_GLOBAL
                    + "WSPEERS")) {
                peerSystems = (String) entry.getValue();
            }
        }

        return AdminsUtil.parseAdmins(admins, auditors, archiveAuditors, peerSystems);
    }
}
