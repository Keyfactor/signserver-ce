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
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.swing.AbstractListModel;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JFileChooser;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.encoders.Hex;

/**
 * Frame showing certificate details.
 *
 * @author Markus Kilås
 * @version $Id$
 */
@SuppressWarnings("PMD.UnusedFormalParameter")
public class ViewCertificateFrame extends javax.swing.JFrame {

    /** Logger for this class. */
    private static final Logger LOG = 
            Logger.getLogger(ViewCertificateFrame.class);

    private final List<X509Certificate> certificates;
    private X509Certificate certificate;

    private List<Field> fields;

    private List<String> usages;

    public ViewCertificateFrame(final List<X509Certificate> certificates) {
        this.certificates = certificates;
        this.certificate = certificates.get(0);
        initComponents();
        chainList.setModel(new AbstractListModel() {

            @Override
            public int getSize() {
                return certificates.size();
            }

            @Override
            public Object getElementAt(int index) {
                return certificates.get(index);
            }
        });
        chainList.setCellRenderer(new DefaultListCellRenderer() {

            @Override
            public Component getListCellRendererComponent(final JList list, Object value, final int index, final boolean isSelected, final boolean cellHasFocus) {
                if (value instanceof X509Certificate) {
                    final X509Certificate cert = (X509Certificate) value;
                    value = cert.getSubjectDN().getName();
                }
                return super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            }

        });
        chainList.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

            @Override
            public void valueChanged(final ListSelectionEvent evt) {
                if (!evt.getValueIsAdjusting()) {
                    viewCertificate((X509Certificate)
                            chainList.getSelectedValue());
                }
            }
        });

        fieldsList.setCellRenderer(new DefaultListCellRenderer() {

            @Override
            public Component getListCellRendererComponent(final JList list, Object value, final int index, final boolean isSelected, final boolean cellHasFocus) {
                if (value instanceof Field) {
                    value = ((Field) value).getName();
                }
                return super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            }

        });
        fieldsList.getSelectionModel().addListSelectionListener(new ListSelectionListener() {

            @Override
            public void valueChanged(final ListSelectionEvent evt) {
                if (!evt.getValueIsAdjusting()) {
                    viewFieldValue((Field) fieldsList.getSelectedValue());
                }
            }
        });

        subjectTextArea.setText(certificate.getSubjectDN().getName());
        issuerTextArea.setText(certificate.getIssuerDN().getName());
        serialNumberField.setText(certificate.getSerialNumber().toString(16));
        notBeforeLabel.setText(String.valueOf(certificate.getNotBefore()));
        notAfterLabel.setText(String.valueOf(certificate.getNotAfter()));

        String fingerprint = "";
        try {
            fingerprint = calcFingerprint(certificate.getEncoded());
        } catch (CertificateEncodingException ex) {
            LOG.error("Error calculating certificate fingerprint", ex);
        }
        fingerprintLabel.setText(fingerprint);

        usages = new ArrayList<>();
        boolean[] keyUsages = certificate.getKeyUsage();
        if (keyUsages != null) {
            // digitalSignature        (0),
            if (keyUsages[0]) {
                usages.add("digitalSignature");
            }
            // nonRepudiation          (1),
            if (keyUsages[1]) {
                usages.add("nonRepudiation");
            }
            // keyEncipherment         (2),
            if (keyUsages[2]) {
                usages.add("keyEncipherment");
            }
            // dataEncipherment        (3),
            if (keyUsages[3]) {
                usages.add("dataEncipherment");
            }
            // keyAgreement            (4),
            if (keyUsages[4]) {
                usages.add("keyAgreement");
            }
            // keyCertSign             (5),
            if (keyUsages[5]) {
                usages.add("keyCertSign");
            }
            // cRLSign                 (6),
            if (keyUsages[6]) {
                usages.add("cRLSign");
            }
            // encipherOnly            (7),
            if (keyUsages[7]) {
                usages.add("encipherOnly");
            }
            // decipherOnly
            if (keyUsages[8]) {
                usages.add("decipherOnly");
            }
        }

        try {
            final List<String> eku = certificate.getExtendedKeyUsage();
            if (eku != null) {
                usages.addAll(eku);
            }
        } catch (CertificateParsingException ex) {
            LOG.error("Error getting extended key usage", ex);
        }

        usagesList.setModel(new AbstractListModel() {

            @Override
            public int getSize() {
                return usages.size();
            }

            @Override
            public Object getElementAt(int index) {
                return usages.get(index);
            }
        });

        chainList.setSelectedIndex(0);
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jTabbedPane1 = new javax.swing.JTabbedPane();
        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        usagesList = new javax.swing.JList();
        jSeparator1 = new javax.swing.JSeparator();
        jLabel2 = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        subjectTextArea = new javax.swing.JTextArea();
        jScrollPane3 = new javax.swing.JScrollPane();
        issuerTextArea = new javax.swing.JTextArea();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        notBeforeLabel = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        fingerprintLabel = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        notAfterLabel = new javax.swing.JLabel();
        jLabel12 = new javax.swing.JLabel();
        serialNumberField = new javax.swing.JTextField();
        jPanel2 = new javax.swing.JPanel();
        jLabel14 = new javax.swing.JLabel();
        jScrollPane4 = new javax.swing.JScrollPane();
        chainList = new javax.swing.JList();
        jLabel15 = new javax.swing.JLabel();
        jScrollPane5 = new javax.swing.JScrollPane();
        fieldsList = new javax.swing.JList();
        jLabel16 = new javax.swing.JLabel();
        jScrollPane6 = new javax.swing.JScrollPane();
        fieldValueEditorPane = new javax.swing.JEditorPane();
        exportButton = new javax.swing.JButton();
        closeButton = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(org.signserver.admin.gui.SignServerAdminGUIApplication.class).getContext().getResourceMap(ViewCertificateFrame.class);
        setTitle(resourceMap.getString("Form.title")); // NOI18N
        setLocationByPlatform(true);
        setName("Form"); // NOI18N

        jTabbedPane1.setName("jTabbedPane1"); // NOI18N

        jPanel1.setName("jPanel1"); // NOI18N

        jLabel1.setFont(resourceMap.getFont("jLabel1.font")); // NOI18N
        jLabel1.setText(resourceMap.getString("jLabel1.text")); // NOI18N
        jLabel1.setName("jLabel1"); // NOI18N

        jScrollPane1.setName("jScrollPane1"); // NOI18N

        usagesList.setModel(new javax.swing.AbstractListModel() {
            String[] strings = { "Item 1", "Item 2", "Item 3", "Item 4", "Item 5" };
            public int getSize() { return strings.length; }
            public Object getElementAt(int i) { return strings[i]; }
        });
        usagesList.setName("usagesList"); // NOI18N
        jScrollPane1.setViewportView(usagesList);

        jSeparator1.setName("jSeparator1"); // NOI18N

        jLabel2.setFont(resourceMap.getFont("jLabel2.font")); // NOI18N
        jLabel2.setText(resourceMap.getString("jLabel2.text")); // NOI18N
        jLabel2.setName("jLabel2"); // NOI18N

        jScrollPane2.setName("jScrollPane2"); // NOI18N

        subjectTextArea.setColumns(20);
        subjectTextArea.setEditable(false);
        subjectTextArea.setLineWrap(true);
        subjectTextArea.setRows(4);
        subjectTextArea.setText(resourceMap.getString("subjectTextArea.text")); // NOI18N
        subjectTextArea.setName("subjectTextArea"); // NOI18N
        jScrollPane2.setViewportView(subjectTextArea);

        jScrollPane3.setName("jScrollPane3"); // NOI18N

        issuerTextArea.setColumns(20);
        issuerTextArea.setEditable(false);
        issuerTextArea.setLineWrap(true);
        issuerTextArea.setRows(4);
        issuerTextArea.setText(resourceMap.getString("issuerTextArea.text")); // NOI18N
        issuerTextArea.setName("issuerTextArea"); // NOI18N
        jScrollPane3.setViewportView(issuerTextArea);

        jLabel3.setFont(resourceMap.getFont("jLabel3.font")); // NOI18N
        jLabel3.setText(resourceMap.getString("jLabel3.text")); // NOI18N
        jLabel3.setName("jLabel3"); // NOI18N

        jLabel4.setFont(resourceMap.getFont("jLabel4.font")); // NOI18N
        jLabel4.setText(resourceMap.getString("jLabel4.text")); // NOI18N
        jLabel4.setName("jLabel4"); // NOI18N

        jLabel5.setFont(resourceMap.getFont("jLabel5.font")); // NOI18N
        jLabel5.setText(resourceMap.getString("jLabel5.text")); // NOI18N
        jLabel5.setName("jLabel5"); // NOI18N

        jLabel6.setText(resourceMap.getString("jLabel6.text")); // NOI18N
        jLabel6.setName("jLabel6"); // NOI18N

        notBeforeLabel.setText(resourceMap.getString("notBeforeLabel.text")); // NOI18N
        notBeforeLabel.setName("notBeforeLabel"); // NOI18N

        jLabel8.setText(resourceMap.getString("jLabel8.text")); // NOI18N
        jLabel8.setName("jLabel8"); // NOI18N

        fingerprintLabel.setText(resourceMap.getString("fingerprintLabel.text")); // NOI18N
        fingerprintLabel.setName("fingerprintLabel"); // NOI18N

        jLabel10.setText(resourceMap.getString("jLabel10.text")); // NOI18N
        jLabel10.setName("jLabel10"); // NOI18N

        notAfterLabel.setText(resourceMap.getString("notAfterLabel.text")); // NOI18N
        notAfterLabel.setName("notAfterLabel"); // NOI18N

        jLabel12.setText(resourceMap.getString("jLabel12.text")); // NOI18N
        jLabel12.setName("jLabel12"); // NOI18N

        serialNumberField.setEditable(false);
        serialNumberField.setText(resourceMap.getString("serialNumberLabel.text")); // NOI18N
        serialNumberField.setInheritsPopupMenu(true);
        serialNumberField.setName("serialNumberLabel"); // NOI18N

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE)
                    .addComponent(jSeparator1, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE)
                    .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel12, javax.swing.GroupLayout.PREFERRED_SIZE, 158, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(serialNumberField, javax.swing.GroupLayout.DEFAULT_SIZE, 608, Short.MAX_VALUE))
                    .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE)
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE)
                    .addComponent(jLabel4, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 158, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(notBeforeLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 614, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel10, javax.swing.GroupLayout.PREFERRED_SIZE, 158, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(notAfterLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 614, Short.MAX_VALUE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel8, javax.swing.GroupLayout.PREFERRED_SIZE, 158, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(fingerprintLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addComponent(jLabel5, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 84, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel12)
                    .addComponent(serialNumberField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel6)
                    .addComponent(notBeforeLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel10)
                    .addComponent(notAfterLabel))
                .addGap(18, 18, 18)
                .addComponent(jLabel5)
                .addGap(2, 2, 2)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel8)
                    .addComponent(fingerprintLabel))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jTabbedPane1.addTab(resourceMap.getString("jPanel1.TabConstraints.tabTitle"), jPanel1); // NOI18N

        jPanel2.setName("jPanel2"); // NOI18N

        jLabel14.setFont(resourceMap.getFont("jLabel14.font")); // NOI18N
        jLabel14.setText(resourceMap.getString("jLabel14.text")); // NOI18N
        jLabel14.setName("jLabel14"); // NOI18N

        jScrollPane4.setName("jScrollPane4"); // NOI18N

        chainList.setModel(new javax.swing.AbstractListModel() {
            String[] strings = { "Signer Certificate", "CSCA Country" };
            public int getSize() { return strings.length; }
            public Object getElementAt(int i) { return strings[i]; }
        });
        chainList.setName("chainList"); // NOI18N
        jScrollPane4.setViewportView(chainList);

        jLabel15.setFont(resourceMap.getFont("jLabel15.font")); // NOI18N
        jLabel15.setText(resourceMap.getString("jLabel15.text")); // NOI18N
        jLabel15.setName("jLabel15"); // NOI18N

        jScrollPane5.setName("jScrollPane5"); // NOI18N

        fieldsList.setModel(new javax.swing.AbstractListModel() {
            String[] strings = { "Item 1", "Item 2", "Item 3", "Item 4", "Item 5" };
            public int getSize() { return strings.length; }
            public Object getElementAt(int i) { return strings[i]; }
        });
        fieldsList.setName("fieldsList"); // NOI18N
        jScrollPane5.setViewportView(fieldsList);

        jLabel16.setFont(resourceMap.getFont("jLabel16.font")); // NOI18N
        jLabel16.setText(resourceMap.getString("jLabel16.text")); // NOI18N
        jLabel16.setName("jLabel16"); // NOI18N

        jScrollPane6.setName("jScrollPane6"); // NOI18N

        fieldValueEditorPane.setEditable(false);
        fieldValueEditorPane.setFont(resourceMap.getFont("fieldValueEditorPane.font")); // NOI18N
        fieldValueEditorPane.setText(resourceMap.getString("fieldValueEditorPane.text")); // NOI18N
        fieldValueEditorPane.setName("fieldValueEditorPane"); // NOI18N
        jScrollPane6.setViewportView(fieldValueEditorPane);

        exportButton.setText(resourceMap.getString("exportButton.text")); // NOI18N
        exportButton.setName("exportButton"); // NOI18N
        exportButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exportButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane6, javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane5, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE)
                    .addComponent(jLabel14, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE)
                    .addComponent(jScrollPane4, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE)
                    .addComponent(jLabel15, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE)
                    .addComponent(jLabel16, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 778, Short.MAX_VALUE)
                    .addComponent(exportButton, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 122, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel14)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel15)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane5, javax.swing.GroupLayout.PREFERRED_SIZE, 186, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel16)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 171, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addComponent(exportButton)
                .addContainerGap())
        );

        jTabbedPane1.addTab(resourceMap.getString("jPanel2.TabConstraints.tabTitle"), jPanel2); // NOI18N

        closeButton.setText(resourceMap.getString("closeButton.text")); // NOI18N
        closeButton.setName("closeButton"); // NOI18N
        closeButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                closeButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(closeButton, javax.swing.GroupLayout.PREFERRED_SIZE, 122, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jTabbedPane1))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jTabbedPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 686, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(closeButton)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void closeButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_closeButtonActionPerformed
        dispose();
    }//GEN-LAST:event_closeButtonActionPerformed

private void exportButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exportButtonActionPerformed
    if (certificate != null) {
        final JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setAcceptAllFileFilterUsed(false);
        final FileFilter pemFilter = new FileNameExtensionFilter("X.509 Certificate (PEM)", "pem");
        final FileFilter pemChainFilter = new FileNameExtensionFilter("X.509 Certificate with chain (PEM)", "pem");
        final FileFilter derFilter = new FileNameExtensionFilter("X.509 Certificate (DER)", "cer", "crt", "der");
        chooser.addChoosableFileFilter(pemFilter);
        chooser.addChoosableFileFilter(derFilter);
        chooser.addChoosableFileFilter(pemChainFilter);
        chooser.setDialogTitle("Save certificate as file");

        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            
            try {
                if (chooser.getFileFilter() == derFilter) {
                    // DER file
                    FileUtils.writeByteArrayToFile(file, certificate.getEncoded());
                } else {
                    // PEM file
                    BufferedOutputStream out = null;
                    try {
                        out = new BufferedOutputStream(new FileOutputStream(file));
                        try (PEMWriter pemWriter = new PEMWriter(new OutputStreamWriter(out))) {
                            if (chooser.getFileFilter() == pemFilter) {
                                pemWriter.writeObject(certificate);
                            } else {
                                for (X509Certificate cert : certificates) {
                                    pemWriter.writeObject(cert);
                                }
                            }
                        }
                    } finally {
                        IOUtils.closeQuietly(out);
                    }
                }
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Exporting certificate failed:\n" + ex.getLocalizedMessage(),
                        "Export", JOptionPane.ERROR_MESSAGE);
            } catch (CertificateEncodingException ex) {
                JOptionPane.showMessageDialog(this, "Unable to encode certificate:\n" + ex.getLocalizedMessage(),
                        "Export", JOptionPane.ERROR_MESSAGE);
            }
        }    
    }
}//GEN-LAST:event_exportButtonActionPerformed

    private void viewCertificate(final X509Certificate certificate) {
        this.certificate = certificate;
        if (certificate == null) {
            fields = null;
            
        } else {
            fields = new ArrayList<>();

            fields.add(new Field("Version",
                    String.valueOf(certificate.getVersion())));
            fields.add(new Field("Serial Number",
            		certificate.getSerialNumber().toString(16)));
            fields.add(new Field("Certificate Signature Algorithm",
                    String.valueOf(certificate.getSigAlgName())));
            fields.add(new Field("Issuer",
                    String.valueOf(certificate.getIssuerDN())));
            fields.add(new Field("Validity Not Before",
                    String.valueOf(certificate.getNotBefore())));
            fields.add(new Field("Validity Not After",
                    String.valueOf(certificate.getNotAfter())));
            fields.add(new Field("Subject",
                    String.valueOf(certificate.getSubjectDN())));
            fields.add(new Field("Subject Public Key Algorithm",
                    String.valueOf(certificate.getPublicKey().getAlgorithm())));
            fields.add(new Field("Subject's Public Key",
                    new String(Hex.encode(certificate.getPublicKey()
                    .getEncoded()))));
            if (certificate.getCriticalExtensionOIDs() != null) {
                for (String extensionOid
                        : certificate.getCriticalExtensionOIDs()) {
                    fields.add(new Field("Critical extension: " + extensionOid,
                            "<Not supported yet>"));
                }
            }
            if (certificate.getNonCriticalExtensionOIDs() != null) {
                for (String extensionOid
                        : certificate.getNonCriticalExtensionOIDs()) {
                    fields.add(new Field("Non critical extension: " + extensionOid,
                            "<Not supported yet>"));
                }
            }
            fields.add(new Field("Certificate Signature Algorithm",
                    String.valueOf(certificate.getSigAlgName())));
            fields.add(new Field("Certificate Signature Value",
                    new String(Hex.encode(certificate.getSignature()))));
            
            fieldsList.setModel(new AbstractListModel() {

                @Override
                public int getSize() {
                    return fields.size();
                }

                @Override
                public Object getElementAt(int index) {
                    return fields.get(index);
                }
            });
        }
    }

    private void viewFieldValue(final Field field) {
        fieldValueEditorPane.setText(field == null ? "" : field.getValue());
    }

    private String calcFingerprint(final byte[] data) {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA1");
            return new String(Hex.encode(md.digest(data)));
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JList chainList;
    private javax.swing.JButton closeButton;
    private javax.swing.JButton exportButton;
    private javax.swing.JEditorPane fieldValueEditorPane;
    private javax.swing.JList fieldsList;
    private javax.swing.JLabel fingerprintLabel;
    private javax.swing.JTextArea issuerTextArea;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel15;
    private javax.swing.JLabel jLabel16;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JLabel notAfterLabel;
    private javax.swing.JLabel notBeforeLabel;
    private javax.swing.JTextField serialNumberField;
    private javax.swing.JTextArea subjectTextArea;
    private javax.swing.JList usagesList;
    // End of variables declaration//GEN-END:variables

    private static final class Field {
        private final String name;
        private final String value;

        public Field(final String name, final String value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }
    }
}